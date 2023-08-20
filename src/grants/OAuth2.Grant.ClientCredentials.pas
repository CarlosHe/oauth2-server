unit OAuth2.Grant.ClientCredentials;

interface

uses
  Web.HTTPApp,
  OAuth2.Contract.ResponseType,
  OAuth2.Contract.Grant.GrantType,
  OAuth2.Grant.AbstractAuthorize;

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
  System.SysUtils,
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.Scope,
  OAuth2.Contract.Entity.AccessToken,
  OAuth2.Exception.ServerException;

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
