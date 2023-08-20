unit OAuth2.Grant.Implicit;

interface

uses
  Web.HTTPApp,
  OAuth2.Contract.Repository.RefreshToken,
  OAuth2.Contract.ResponseType,
  OAuth2.Contract.Grant.GrantType,
  OAuth2.RequestType.AuthorizationRequest,
  OAuth2.Grant.AbstractAuthorize;

type

  TOAuth2ImplicitGrant = class(TAbstractAuthorizeGrant)
  private
    { private declarations }
    FAccessTokenTTL: Int64;
    FQueryDelimiter: string;
  protected
    { protected declarations }
    function GetClientRedirectUri(AuthorizationRequest: TOAuth2AuthorizationRequest): string;
  public
    { public declarations }
    constructor Create(AAccessTokenTTL: Int64; const AQueryDelimiter: string = '#');
    procedure SetRefreshTokenTTL(ARefreshTokenTTL: Int64); override;
    procedure SetRefreshTokenRepository(ARefreshTokenRepository: IOAuth2RefreshTokenRepository); override;
    function CanRespondToAccessTokenRequest(ARequest: TWebRequest): Boolean; override;
    function GetIdentifier: string; override;
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType; override;
    function CanRespondToAuthorizationRequest(ARequest: TWebRequest): Boolean; override;
    function ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest; override;
    function CompleteAuthorizationRequest(AAuthorizationRequest: TOAuth2AuthorizationRequest): IOAuth2ResponseType; override;
    class function New(AAccessTokenTTL: Int64; const AQueryDelimiter: string = '#'): IOAuth2GrantTypeGrant;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  System.Generics.Collections,
  OAuth2.ResponseType.RedirectResponse,
  OAuth2.Exception.ServerException,
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.AuthCode,
  OAuth2.Contract.Entity.Scope,
  OAuth2.Contract.Entity.AccessToken;

{ TOAuth2ImplicitGrant }

function TOAuth2ImplicitGrant.CanRespondToAccessTokenRequest(ARequest: TWebRequest): Boolean;
begin
  Result := False;
end;

function TOAuth2ImplicitGrant.CanRespondToAuthorizationRequest(ARequest: TWebRequest): Boolean;
begin
  Result :=
    (ARequest.QueryFields.IndexOfName('response_type') > -1)
    and (ARequest.QueryFields.Values['response_type'] = 'token')
    and (ARequest.QueryFields.IndexOfName('client_id') > -1)
    and (not ARequest.QueryFields.Values['client_id'].IsEmpty)
end;

function TOAuth2ImplicitGrant.CompleteAuthorizationRequest(AAuthorizationRequest: TOAuth2AuthorizationRequest): IOAuth2ResponseType;
var
  LFinalRedirectUri: string;
  LResponse: TOAuth2RedirectResponse;
  LFinalizeScopes: TArray<IOAuth2ScopeEntity>;
  LAccessToken: IOAuth2AccessTokenEntity;
begin
  Result := nil;

  if AAuthorizationRequest.GetUser = nil then
    raise EOAuth2ServerException.InvalidRequest('An instance of UserEntityInterface should be set on the AuthorizationRequest');
  LFinalRedirectUri := AAuthorizationRequest.GetRedirectUri;
  if LFinalRedirectUri.IsEmpty then
    LFinalRedirectUri := GetClientRedirectUri(AAuthorizationRequest);

  if AAuthorizationRequest.IsAuthorizationApproved then
  begin

    LFinalizeScopes := GetScopeRepository.FinalizeScopes(
      AAuthorizationRequest.GetScopes,
      GetIdentifier,
      AAuthorizationRequest.GetClient,
      AAuthorizationRequest.GetUser.GetIdentifier
      );

    LAccessToken := IssueAccessToken(
      FAccessTokenTTL,
      AAuthorizationRequest.GetClient,
      AAuthorizationRequest.GetUser.GetIdentifier,
      LFinalizeScopes
      );

    LResponse := TOAuth2RedirectResponse.Create;
    Result := LResponse;
    LResponse.SetRedirectUri(MakeRedirectUri(
      LFinalRedirectUri,
      [
      TPair<string, string>.Create('access_token', LAccessToken.ToString),
      TPair<string, string>.Create('token_type', 'Bearer'),
      TPair<string, string>.Create('expires_in', DateTimeToUnix(IncSecond(LAccessToken.GetExpiryDateTime, FAccessTokenTTL)).ToString),
      TPair<string, string>.Create('state', AAuthorizationRequest.GetCodeChallengeMethod)
      ],
      FQueryDelimiter
      ));
  end
  else
  begin
    raise EOAuth2ServerException.AccessDenied(
      'The user denied the request',
      MakeRedirectUri(LFinalRedirectUri, [TPair<string, string>.Create('state', AAuthorizationRequest.GetState)])
      )
  end;

end;

constructor TOAuth2ImplicitGrant.Create(AAccessTokenTTL: Int64; const AQueryDelimiter: string);
begin
  FAccessTokenTTL := AAccessTokenTTL;
  FQueryDelimiter := AQueryDelimiter;
end;

function TOAuth2ImplicitGrant.GetClientRedirectUri(AuthorizationRequest: TOAuth2AuthorizationRequest): string;
begin
  Result := '';
  if Length(AuthorizationRequest.GetClient.GetRedirectUri) > 0 then
    Result := AuthorizationRequest.GetClient.GetRedirectUri[0]
end;

function TOAuth2ImplicitGrant.GetIdentifier: string;
begin
  Result := 'implicit';
end;

class function TOAuth2ImplicitGrant.New(AAccessTokenTTL: Int64; const AQueryDelimiter: string): IOAuth2GrantTypeGrant;
begin
  Result := TOAuth2ImplicitGrant.Create(AAccessTokenTTL, AQueryDelimiter);
end;

function TOAuth2ImplicitGrant.RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType;
begin
  raise Exception.Create('This grant does not used this method');
end;

procedure TOAuth2ImplicitGrant.SetRefreshTokenRepository(ARefreshTokenRepository: IOAuth2RefreshTokenRepository);
begin
  raise Exception.Create('The Implicit Grant does not return refresh tokens');
end;

procedure TOAuth2ImplicitGrant.SetRefreshTokenTTL(ARefreshTokenTTL: Int64);
begin
  raise Exception.Create('The Implicit Grant does not return refresh tokens');
end;

function TOAuth2ImplicitGrant.ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest;
var
  LClientId: string;
  LClient: IOAuth2ClientEntity;
  LRedirectUri: string;
  LScopes: TArray<IOAuth2ScopeEntity>;
  LStateParameter: string;
  LAuthorizationRequest: TOAuth2AuthorizationRequest;
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

    Result := LAuthorizationRequest;
  except
    LAuthorizationRequest.Free;
  end;

end;

end.
