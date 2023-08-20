unit OAuth2.Grant.RefreshToken;

interface

uses
  System.JSON,
  Web.HTTPApp,
  OAuth2.Contract.Repository.RefreshToken,
  OAuth2.Contract.ResponseType,
  OAuth2.Contract.Grant.GrantType,
  OAuth2.Grant.AbstractAuthorize;

type

  TOAuth2RefreshTokenGrant = class(TAbstractAuthorizeGrant)
  private
    { private declarations }
  protected
    { protected declarations }
    function ValidateOldRefreshToken(ARequest: TWebRequest; AClientId: string): TJSONObject;
  public
    { public declarations }
    constructor Create(ARefreshTokenRepository: IOAuth2RefreshTokenRepository);
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType; override;
    function GetIdentifier: string; override;
    class function New(ARefreshTokenRepository: IOAuth2RefreshTokenRepository): IOAuth2GrantTypeGrant;
  end;

implementation

uses
  System.SysUtils,
  System.StrUtils,
  System.Generics.Collections,
  OAuth2.Contract.Entity.Scope,
  OAuth2.Contract.Entity.AccessToken,
  OAuth2.Contract.Entity.RefreshToken,
  OAuth2.Contract.Entity.Client,
  OAuth2.Exception.ServerException,
  OAuth2.Provider.Crypto;

{ TOAuth2RefreshTokenGrant }

constructor TOAuth2RefreshTokenGrant.Create(ARefreshTokenRepository: IOAuth2RefreshTokenRepository);
begin
  SetRefreshTokenRepository(ARefreshTokenRepository);
  SetRefreshTokenTTL(60 * 60 * 24 * 30);
end;

function TOAuth2RefreshTokenGrant.GetIdentifier: string;
begin
  Result := 'refresh_token';
end;

class function TOAuth2RefreshTokenGrant.New(ARefreshTokenRepository: IOAuth2RefreshTokenRepository): IOAuth2GrantTypeGrant;
begin
  Result := TOAuth2RefreshTokenGrant.Create(ARefreshTokenRepository);
end;

function TOAuth2RefreshTokenGrant.RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType;
var
  LClient: IOAuth2ClientEntity;
  LOldRefreshToken: TJSONObject;
  LScopes: TArray<IOAuth2ScopeEntity>;
  LScopePayload: TJSONArray;
  LStringScopesCollection: TArray<string>;
  I: Integer;
  LAccessToken: IOAuth2AccessTokenEntity;
  LRefreshToken: IOAuth2RefreshTokenEntity;
begin
  Result := AResponseType;

  LClient := ValidateClient(ARequest);
  LOldRefreshToken := ValidateOldRefreshToken(ARequest, LClient.GetIdentifier);
  LScopePayload := LOldRefreshToken.GetValue<TJSONArray>('scopes');

  if LScopePayload = nil then
    raise EOAuth2ServerException.InvalidRefreshToken('Invalid scopes data');

  for I := 0 to Pred(LScopePayload.Count) do
    LStringScopesCollection := LStringScopesCollection + [LScopePayload.Items[I].Value];

  LScopes := ValidateScopes(GetQueryStringParameter('scope', ARequest, string.Join(SCOPE_DELIMITER_STRING, LStringScopesCollection)));

  for I := Low(LScopes) to High(LScopes) do
  begin
    if IndexStr(LScopes[I].GetIdentifier, LStringScopesCollection) = -1 then
      raise EOAuth2ServerException.InvalidScope(LScopes[I].GetIdentifier);
  end;

  GetAccessTokenRepository.RevokeAccessToken(LOldRefreshToken.GetValue<string>('access_token_id'));
  GetRefreshTokenRepository.RevokeRefreshToken(LOldRefreshToken.GetValue<string>('refresh_token_id'));

  LAccessToken := IssueAccessToken(AAccessTokenTTL, LClient, LOldRefreshToken.GetValue<string>('user_id'), LScopes);

  AResponseType.SetAccessToken(LAccessToken);

  LRefreshToken := IssueRefreshToken(LAccessToken);

  if LRefreshToken <> nil then
    AResponseType.SetRefreshToken(LRefreshToken);

end;

function TOAuth2RefreshTokenGrant.ValidateOldRefreshToken(ARequest: TWebRequest; AClientId: string): TJSONObject;
var
  LEncryptedRefreshToken: string;
  LRefreshToken: string;
  LRefreshTokenData: TJSONObject;
  LClientId: string;
  LExpireTime: TDateTime;
  LRefreshTokenId: string;
begin
  Result := nil;

  LEncryptedRefreshToken := GetRequestParameter('refresh_token', ARequest, EmptyStr);

  if LEncryptedRefreshToken.IsEmpty then
    raise EOAuth2ServerException.InvalidRefreshToken('Cannot decrypt the refresh token');

  LRefreshToken := TOAuth2CryptoProvider.DecryptWithPassword(LEncryptedRefreshToken, GetEncryptionKey);

  LRefreshTokenData := TJSONObject.ParseJSONValue(LRefreshToken) as TJSONObject;
  try
    if LRefreshTokenData = nil then
      raise EOAuth2ServerException.InvalidRefreshToken('Invalid refresh token data');

    LRefreshTokenData.TryGetValue<string>('client_id', LClientId);
    if LClientId <> AClientId then
      raise EOAuth2ServerException.InvalidRefreshToken('Invalid refresh token data');

    LRefreshTokenData.TryGetValue<TDateTime>('expire_time', LExpireTime);
    if LExpireTime < Now() then
      raise EOAuth2ServerException.InvalidRefreshToken('Token has expired');

    LRefreshTokenData.TryGetValue<string>('refresh_token_id', LRefreshTokenId);
    if LRefreshTokenId.IsEmpty then
      raise EOAuth2ServerException.InvalidRefreshToken('Invalid refresh token id');

    if GetRefreshTokenRepository.IsRefreshTokenRevoked(LRefreshTokenId) then
      raise EOAuth2ServerException.InvalidRefreshToken('Token has been revoked');

    Result := LRefreshTokenData;
  except
    LRefreshTokenData.Free;
  end;
end;

end.
