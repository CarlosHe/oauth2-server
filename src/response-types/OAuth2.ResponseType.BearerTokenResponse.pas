unit OAuth2.ResponseType.BearerTokenResponse;

interface

uses
  System.JSON,
  Web.HTTPApp,
  OAuth2.Contract.Entity.AccessToken,
  OAuth2.ResponseType.Abstract;

type

  TOAuth2BearerTokenResponse = class(TOAuth2AbstractResponseType)
  private
    { private declarations }
  protected
    { protected declarations }
  public
    { public declarations }
    function GenerateHttpResponse(AResponse: TWebResponse): TWebResponse; override;
    function GetExtraParams(AAccessToken: IOAuth2AccessTokenEntity): TJSONObject; virtual;
  end;

implementation

uses
  System.Generics.Collections,
  System.SysUtils,
  System.DateUtils,
  OAuth2.Provider.Crypto;

{ TOAuth2BearerTokenResponse }

function TOAuth2BearerTokenResponse.GenerateHttpResponse(AResponse: TWebResponse): TWebResponse;
var
  LExpireDateTime: Int64;
  LResponseParams: TJSONObject;
  LScopes: TJSONArray;
  LRefreshTokenPayload: TJSONObject;
  LExtraParams: TJSONObject;
  I: Integer;
begin
  inherited;
  Result := AResponse;
  LExpireDateTime := DateTimeToUnix(AccessToken.GetExpiryDateTime);
  LResponseParams := TJSONObject.Create;
  try

    LResponseParams.AddPair('token_type', 'Bearer');
    LResponseParams.AddPair('expires_in', TJSONNumber.Create(LExpireDateTime));
    LResponseParams.AddPair('access_token', AccessToken.ToString);

    if RefreshToken <> nil then
    begin
      LRefreshTokenPayload := TJSONObject.Create;
      try
        LRefreshTokenPayload.AddPair('client_id', AccessToken.GetClient.GetIdentifier);
        LRefreshTokenPayload.AddPair('refresh_token_id', RefreshToken.GetIdentifier);
        LRefreshTokenPayload.AddPair('access_token_id', AccessToken.GetIdentifier);
        LScopes := TJSONArray.Create;
        LRefreshTokenPayload.AddPair('scopes', LScopes);
        for I := Low(AccessToken.GetScopes) to High(AccessToken.GetScopes) do
        begin
          LScopes.Add(AccessToken.GetScopes[I].GetIdentifier);
        end;
        LRefreshTokenPayload.AddPair('user_id', AccessToken.GetUserIdentifier);
        LRefreshTokenPayload.AddPair('expire_time', TJSONNumber.Create(DateTimeToUnix(RefreshToken.GetExpiryDateTime)));

        LResponseParams.AddPair('refresh_token', TOAuth2CryptoProvider.EncryptWithPassword(LRefreshTokenPayload.ToJSON, EncryptionKey));

      finally
        LRefreshTokenPayload.Free;
      end;
    end;

    LExtraParams := GetExtraParams(AccessToken);
    if LExtraParams <> nil then
    begin
      for I := 0 to Pred(LExtraParams.Count) do
      begin
        LResponseParams.AddPair(LExtraParams.Pairs[I].JsonString.Value, LExtraParams.Pairs[I].JsonValue.Clone as TJSONValue);
      end;
    end;

    AResponse.StatusCode := 200;
    AResponse.CustomHeaders.AddPair('pragma', 'no-cache');
    AResponse.CustomHeaders.AddPair('cache-control', 'no-store');
    AResponse.ContentType := 'application/json; charset=UTF-8';

    AResponse.Content := LResponseParams.ToJSON;

  finally
    LResponseParams.Free;
  end;
end;

function TOAuth2BearerTokenResponse.GetExtraParams(AAccessToken: IOAuth2AccessTokenEntity): TJSONObject;
begin
  Result := nil;
end;

end.
