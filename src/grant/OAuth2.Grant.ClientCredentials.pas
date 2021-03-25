unit OAuth2.Grant.ClientCredentials;

interface

uses
  OAuth2.Grant.AbstractAuthorize,
  OAuth2.ResponseType.Contract,
  OAuth2.Grant.GrantType.Contract,
  Web.HTTPApp;

type

  TOAuth2ClientCredentialsGrant = class(TAbstractAuthorizeGrant)
  private
    { private declarations }
  protected
    { protected declarations }
  public
    { public declarations }
    function GetIdentifier: string; override;
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType; override;
    class function New: IOAuth2GrantTypeGrant;
  end;

implementation

uses
  OAuth2.Entity.Client.Contract,
  OAuth2.Entity.Scope.Contract,
  OAuth2.Entity.AccessToken.Contract,
  OAuth2.Exception.ServerException,
  System.SysUtils;

{ TOAuth2ClientCredentialsGrant }

function TOAuth2ClientCredentialsGrant.GetIdentifier: string;
begin
  Result := 'client_credentials';
end;

class function TOAuth2ClientCredentialsGrant.New: IOAuth2GrantTypeGrant;
begin
  Result := TOAuth2ClientCredentialsGrant.Create;
end;

function TOAuth2ClientCredentialsGrant.RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType;
var
  LClientId: string;
  LClient: IOAuth2ClientEntity;
  LScopes: TArray<IOAuth2ScopeEntity>;
  LFinalizedScopes: TArray<IOAuth2ScopeEntity>;
  LAccessToken: IOAuth2AccessTokenEntity;
begin

  Result := AResponseType;

  LClientId := GetClientCredentials(ARequest).GetClientId;

  LClient := GetClientEntityOrFail(LClientId, ARequest);

  if (not LClient.IsConfidential) then
    raise EOAuth2ServerException.InvalidClient(ARequest);

  ValidateClient(ARequest);

  LScopes := ValidateScopes(GetRequestParameter('scopes', ARequest, EmptyStr));

  LFinalizedScopes := GetScopeRepository.FinalizeScopes(
    LScopes,
    GetIdentifier,
    LClient
    );

  LAccessToken := IssueAccessToken(AAccessTokenTTL, LClient, EmptyStr, LFinalizedScopes);

  AResponseType.SetAccessToken(LAccessToken);

end;

end.
