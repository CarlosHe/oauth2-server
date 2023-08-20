unit OAuth2.Grant.AuthCode;

interface

uses
  System.JSON,
  System.Generics.Collections,
  Web.HTTPApp,
  OAuth2.Contract.CodeChallengeVerifier,
  OAuth2.CodeChallengeVerifier.PlainVerifier,
  OAuth2.CodeChallengeVerifier.S256Verifier,
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Repository.AuthCode,
  OAuth2.Contract.Repository.RefreshToken,
  OAuth2.Contract.ResponseType,
  OAuth2.Grant.AbstractAuthorize,
  OAuth2.RequestType.AuthorizationRequest,
  OAuth2.Contract.Grant.GrantType;

type

  TOAuth2AuthCodeGrant = class(TAbstractAuthorizeGrant)
  private
    { private declarations }
    FAuthCodeTTL: Int64;
    FRequireCodeChallengeForPublicClients: Boolean;
    FCodeChallengeVerifiers: TDictionary<string, IOAuth2CodeChallengeVerifier>;
  protected
    { protected declarations }
    procedure ValidateAuthorizationCode(AAuthCodePayload: TJSONObject; AClient: IOAuth2ClientEntity; ARequest: TWebRequest);
    function GetClientRedirectUri(AuthorizationRequest: TOAuth2AuthorizationRequest): string;
  public
    { public declarations }
    constructor Create(AAuthCodeRepository: IOAuth2AuthCodeRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository; AAuthCodeTTL: Int64);
    destructor Destroy; override;
    procedure DisableRequireCodeChallengeForPublicClients;
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType; override;
    function GetIdentifier: string; override;
    function CanRespondToAuthorizationRequest(ARequest: TWebRequest): Boolean; override;
    function ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest; override;
    function CompleteAuthorizationRequest(AAuthorizationRequest: TOAuth2AuthorizationRequest): IOAuth2ResponseType; override;
    class function New(AAuthCodeRepository: IOAuth2AuthCodeRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository; AAuthCodeTTL: Int64): IOAuth2GrantTypeGrant;
  end;

implementation

uses
  System.RegularExpressions,
  System.DateUtils,
  System.SysUtils,
  System.NetEncoding,
  OAuth2.Contract.Entity.AccessToken,
  OAuth2.Contract.Entity.AuthCode,
  OAuth2.Contract.Entity.RefreshToken,
  OAuth2.Contract.Entity.Scope,
  OAuth2.ResponseType.RedirectResponse,
  OAuth2.Exception.ServerException,
  OAuth2.Provider.Crypto;

{ TOAuth2AuthCodeGrant }

function TOAuth2AuthCodeGrant.CanRespondToAuthorizationRequest(ARequest: TWebRequest): Boolean;
begin
  Result :=
    (ARequest.QueryFields.IndexOfName('response_type') > -1)
    and (ARequest.QueryFields.Values['response_type'] = 'code')
    and (ARequest.QueryFields.IndexOfName('client_id') > -1)
    and (not ARequest.QueryFields.Values['client_id'].IsEmpty)
end;

function TOAuth2AuthCodeGrant.CompleteAuthorizationRequest(AAuthorizationRequest: TOAuth2AuthorizationRequest): IOAuth2ResponseType;
var
  LFinalRedirectUri: string;
  LAuthCode: IOAuth2AuthCodeEntity;
  LPayload: TJSONObject;
  LScopesPayload: TJSONArray;
  I: Integer;
  LResponse: TOAuth2RedirectResponse;
begin
  Result := nil;

  if AAuthorizationRequest.GetUser = nil then
    raise EOAuth2ServerException.InvalidRequest('An instance of UserEntityInterface should be set on the AuthorizationRequest');
  LFinalRedirectUri := AAuthorizationRequest.GetRedirectUri;
  if LFinalRedirectUri.IsEmpty then
    LFinalRedirectUri := GetClientRedirectUri(AAuthorizationRequest);

  if AAuthorizationRequest.IsAuthorizationApproved then
  begin
    LAuthCode := IssueAuthCode(
      FAuthCodeTTL,
      AAuthorizationRequest.GetClient,
      AAuthorizationRequest.GetUser.GetIdentifier,
      AAuthorizationRequest.GetRedirectUri,
      AAuthorizationRequest.GetScopes
      );
    LPayload := TJSONObject.Create;
    try
      LPayload.AddPair('client_id', LAuthCode.GetClient.GetIdentifier);
      LPayload.AddPair('redirect_uri', LAuthCode.GetRedirectUri);
      LPayload.AddPair('auth_code_id', LAuthCode.GetIdentifier);
      LScopesPayload := TJSONArray.Create;
      LPayload.AddPair('scopes', LScopesPayload);
      for I := 0 to Pred(Length(LAuthCode.GetScopes)) do
        LScopesPayload.Add(LAuthCode.GetScopes[I].GetIdentifier);
      LPayload.AddPair('user_id', LAuthCode.GetUserIdentifier);
      LPayload.AddPair('expire_time', TJSONNumber.Create(DateTimeToUnix(IncSecond(Now, FAuthCodeTTL))));
      LPayload.AddPair('code_challenge', AAuthorizationRequest.GetCodeChallenge);
      LPayload.AddPair('code_challenge_method', AAuthorizationRequest.GetCodeChallengeMethod);

      LResponse := TOAuth2RedirectResponse.Create;
      Result := LResponse;
      LResponse.SetRedirectUri(MakeRedirectUri(
        LFinalRedirectUri,
        [
        TPair<string, string>.Create('code', TOAuth2CryptoProvider.EncryptWithPassword(LPayload.ToJSON, GetEncryptionKey)),
        TPair<string, string>.Create('state', AAuthorizationRequest.GetState)
        ]
        ));
    finally
      LPayload.Free;
    end;

  end
  else
  begin
    raise EOAuth2ServerException.AccessDenied(
      'The user denied the request',
      MakeRedirectUri(LFinalRedirectUri, [TPair<string, string>.Create('state', AAuthorizationRequest.GetState)])
      )
  end;

end;

constructor TOAuth2AuthCodeGrant.Create(AAuthCodeRepository: IOAuth2AuthCodeRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository; AAuthCodeTTL: Int64);
var
  LPlainVerifier: IOAuth2CodeChallengeVerifier;
  LS256Verifier: IOAuth2CodeChallengeVerifier;
begin
  FRequireCodeChallengeForPublicClients := True;
  FCodeChallengeVerifiers := TDictionary<string, IOAuth2CodeChallengeVerifier>.Create;
  SetAuthCodeRepository(AAuthCodeRepository);
  SetRefreshTokenRepository(ARefreshTokenRepository);
  SetRefreshTokenTTL(60 * 60 * 24 * 30);
  FAuthCodeTTL := AAuthCodeTTL;

  LPlainVerifier := TOAuth2PlainVerifier.Create;
  FCodeChallengeVerifiers.Add(LPlainVerifier.GetMethod, LPlainVerifier);

  LS256Verifier := TOAuth2S256Verifier.Create;
  FCodeChallengeVerifiers.Add(LS256Verifier.GetMethod, LS256Verifier);
end;

destructor TOAuth2AuthCodeGrant.Destroy;
begin
  FCodeChallengeVerifiers.Free;
  inherited;
end;

procedure TOAuth2AuthCodeGrant.DisableRequireCodeChallengeForPublicClients;
begin
  FRequireCodeChallengeForPublicClients := False;
end;

function TOAuth2AuthCodeGrant.GetClientRedirectUri(AuthorizationRequest: TOAuth2AuthorizationRequest): string;
begin
  Result := '';
  if Length(AuthorizationRequest.GetClient.GetRedirectUri) > 0 then
    Result := AuthorizationRequest.GetClient.GetRedirectUri[0]
end;

function TOAuth2AuthCodeGrant.GetIdentifier: string;
begin
  Result := 'authorization_code';
end;

class function TOAuth2AuthCodeGrant.New(AAuthCodeRepository: IOAuth2AuthCodeRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository;
  AAuthCodeTTL: Int64): IOAuth2GrantTypeGrant;
begin
  Result := TOAuth2AuthCodeGrant.Create(AAuthCodeRepository, ARefreshTokenRepository, AAuthCodeTTL);
end;

function TOAuth2AuthCodeGrant.RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType;
var
  LClientId: string;
  LClient: IOAuth2ClientEntity;
  LAccessToken: IOAuth2AccessTokenEntity;
  LRefreshToken: IOAuth2RefreshTokenEntity;
  LEncryptedAuthCode: string;
  LAuthCodePayload: TJSONObject;
  LScopes: TArray<IOAuth2ScopeEntity>;
  LJSONArrayScopes: TJSONArray;
  LStringScopesCollection: TArray<string>;
  LCodeChallenge: string;
  LCodeVerifier: string;
  LCodeChallengeMethod: string;
  LCodeChallengeVerifier: IOAuth2CodeChallengeVerifier;
  I: Integer;
begin
  Result := nil;

  LClientId := GetClientCredentials(ARequest).GetClientId;
  LClient := GetClientEntityOrFail(LClientId, ARequest);

  if LClient.IsConfidential then
    ValidateClient(ARequest);

  LEncryptedAuthCode := TURLEncoding.URL.URLDecode(GetRequestParameter('code', ARequest, EmptyStr));

  if LEncryptedAuthCode.IsEmpty then
    raise EOAuth2ServerException.InvalidRequest('code');

  try
    LAuthCodePayload := TJSONObject.ParseJSONValue(TOAuth2CryptoProvider.DecryptWithPassword(LEncryptedAuthCode, GetEncryptionKey)) as TJSONObject;
    try
      ValidateAuthorizationCode(LAuthCodePayload, LClient, ARequest);

      LJSONArrayScopes := LAuthCodePayload.GetValue<TJSONArray>('scopes');

      for I := 0 to Pred(LJSONArrayScopes.Count) do
        LStringScopesCollection := LStringScopesCollection + [LJSONArrayScopes.Items[I].Value];

      LScopes := GetScopeRepository.FinalizeScopes(
        ValidateScopes(string.Join(' ', LStringScopesCollection)),
        GetIdentifier,
        LClient,
        LAuthCodePayload.GetValue<string>('user_id')
        );

      if LAuthCodePayload.TryGetValue<string>('code_challenge', LCodeChallenge) then
      begin
        if not LCodeChallenge.IsEmpty then
        begin
          LCodeVerifier := GetRequestParameter('code_verifier', ARequest, EmptyStr);
          if LCodeVerifier.IsEmpty then
            raise EOAuth2ServerException.InvalidRequest('code_verifier');

          if not TRegEx.IsMatch(LCodeVerifier, '^[A-Za-z0-9-._~]{43,128}$') then
            raise EOAuth2ServerException.InvalidRequest('code_verifier', 'Code Verifier must follow the specifications of RFC-7636.');

          if LAuthCodePayload.TryGetValue('code_challenge_method', LCodeChallengeMethod) then
          begin
            if FCodeChallengeVerifiers.TryGetValue(LCodeChallengeMethod, LCodeChallengeVerifier) then
            begin
              if not LCodeChallengeVerifier.VerifyCodeChallenge(LCodeVerifier, LCodeChallenge) then
                raise EOAuth2ServerException.InvalidGrant('Failed to verify ''code_verifier''.');
            end
            else
              raise EOAuth2ServerException.ServerError(Format('Unsupported code challenge method ''%s''', [LCodeChallengeMethod]));
          end;

        end;
      end;

      LAccessToken := IssueAccessToken(AAccessTokenTTL, LClient, LAuthCodePayload.GetValue<string>('user_id'), LScopes);
      AResponseType.SetAccessToken(LAccessToken);

      LRefreshToken := IssueRefreshToken(LAccessToken);

      if LRefreshToken <> nil then
      begin
        AResponseType.SetRefreshToken(LRefreshToken);
      end;

      GetAuthCodeRepository.RevokeAuthCode(LAuthCodePayload.GetValue<string>('auth_code_id'));

      Result := AResponseType;
    finally
      LAuthCodePayload.Free;
    end;
  except
    on E: EOAuth2ServerException do
      raise;
    on E: Exception do
      raise EOAuth2ServerException.InvalidRequest('code', 'Cannot decrypt the authorization code');
  end;

end;

procedure TOAuth2AuthCodeGrant.ValidateAuthorizationCode(AAuthCodePayload: TJSONObject; AClient: IOAuth2ClientEntity; ARequest: TWebRequest);
var
  LAuthCodeId: string;
  LClientId: string;
  LExpireTime: Int64;
  LRedirectUri: string;
  LPayloadRedirectUri: string;
begin
  if not AAuthCodePayload.TryGetValue<string>('auth_code_id', LAuthCodeId) then
    raise EOAuth2ServerException.InvalidRequest('code', 'Authorization code malformed');

  AAuthCodePayload.TryGetValue<Int64>('expire_time', LExpireTime);
  if (LExpireTime < DateTimeToUnix(Now())) then
    raise EOAuth2ServerException.InvalidRequest('code', 'Authorization code has expired');

  if GetAuthCodeRepository.IsAuthCodeRevoked(LAuthCodeId) then
    raise EOAuth2ServerException.InvalidRequest('code', 'Authorization code has been revoked');

  AAuthCodePayload.TryGetValue<string>('client_id', LClientId);
  if (LClientId <> AClient.GetIdentifier) then
    raise EOAuth2ServerException.InvalidRequest('code', 'Authorization code was not issued to this client');

  AAuthCodePayload.TryGetValue<string>('redirect_uri', LPayloadRedirectUri);
  LRedirectUri := GetRequestParameter('redirect_uri', ARequest, EmptyStr);

  if (not LPayloadRedirectUri.IsEmpty) and (LRedirectUri.IsEmpty) then
    raise EOAuth2ServerException.InvalidRequest('redirect_uri');

  if LPayloadRedirectUri <> LRedirectUri then
    raise EOAuth2ServerException.InvalidRequest('redirect_uri', 'Invalid redirect URI');

end;

function TOAuth2AuthCodeGrant.ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest;
var
  LClientId: string;
  LClient: IOAuth2ClientEntity;
  LRedirectUri: string;
  LDefaultClientRedirectUri: string;
  LScopes: TArray<IOAuth2ScopeEntity>;
  LStateParameter: string;
  LAuthorizationRequest: TOAuth2AuthorizationRequest;
  LCodeChallenge: string;
  LCodeChallengeMethod: string;
  LCodeChallengeVerifier: IOAuth2CodeChallengeVerifier;
begin
  Result := nil;

  LClientId := GetQueryStringParameter('client_id', ARequest, EmptyStr);
  if LClientId.IsEmpty then
    raise EOAuth2ServerException.InvalidRequest('client_id');

  LClient := GetClientEntityOrFail(LClientId, ARequest);

  LRedirectUri := GetQueryStringParameter('redirect_uri', ARequest, EmptyStr);

  if (not LRedirectUri.IsEmpty) then
    ValidateRedirectUri(LRedirectUri, LClient, ARequest)
  else if (Length(LClient.GetRedirectUri) = 0) then
    raise EOAuth2ServerException.InvalidClient(ARequest);

  if Length(LClient.GetRedirectUri) > 0 then
    LDefaultClientRedirectUri := LClient.GetRedirectUri[0];

  LScopes := ValidateScopes(GetQueryStringParameter('scope', ARequest, GetDefaultScope));

  LStateParameter := GetQueryStringParameter('state', ARequest, EmptyStr);

  LAuthorizationRequest := TOAuth2AuthorizationRequest.Create;
  try
    LAuthorizationRequest.SetGrantTypeId(GetIdentifier);
    LAuthorizationRequest.SetClient(LClient);
    LAuthorizationRequest.SetRedirectUri(LRedirectUri);
    if not LStateParameter.IsEmpty then
      LAuthorizationRequest.SetState(LStateParameter);
    LAuthorizationRequest.SetScopes(LScopes);

    LCodeChallenge := GetQueryStringParameter('code_challenge', ARequest, EmptyStr);

    if (not LCodeChallenge.IsEmpty) then
    begin
      LCodeChallengeMethod := GetQueryStringParameter('code_challenge_method', ARequest, 'plain');

      if not FCodeChallengeVerifiers.TryGetValue(LCodeChallengeMethod, LCodeChallengeVerifier) then
      begin
        raise EOAuth2ServerException.InvalidRequest(
          'code_challenge_method',
          Format('Code challenge method must be one of ''%s''', [string.Join(''', ''', FCodeChallengeVerifiers.Keys.ToArray)])
          );
      end;

      if not TRegEx.IsMatch(LCodeChallenge, '^[A-Za-z0-9-._~]{43,128}$') then
        raise EOAuth2ServerException.InvalidRequest('code_verifier', 'Code Verifier must follow the specifications of RFC-7636.');

      LAuthorizationRequest.SetCodeChallenge(LCodeChallenge);
      LAuthorizationRequest.SetCodeChallengeMethod(LCodeChallengeMethod);
    end
    else if (FRequireCodeChallengeForPublicClients) and (not LClient.IsConfidential) then
      EOAuth2ServerException.InvalidRequest('code_challenge', 'Code challenge must be provided for public clients');

    Result := LAuthorizationRequest;
  except
    LAuthorizationRequest.Free;
  end;
end;

end.
