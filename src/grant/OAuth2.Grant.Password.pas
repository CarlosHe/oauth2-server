unit OAuth2.Grant.Password;

interface

uses
  OAuth2.Grant.AbstractAuthorize,
  OAuth2.Repository.User.Contract,
  OAuth2.Repository.RefreshToken.Contract,
  OAuth2.ResponseType.Contract,
  OAuth2.Entity.User.Contract,
  OAuth2.Entity.Client.Contract,
  OAuth2.Grant.GrantType.Contract,
  Web.HTTPApp;

type

  TOAuth2PasswordGrant = class(TAbstractAuthorizeGrant)
  private
    { private declarations }
  protected
    { protected declarations }
    function ValidateUser(ARequest: TWebRequest; AClient: IOAuth2ClientEntity): IOAuth2UserEntity;
  public
    { public declarations }
    constructor Create(AUserRepository: IOAuth2UserRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository);
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType; override;
    function GetIdentifier: string; override;
    class function New(AUserRepository: IOAuth2UserRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository): IOAuth2GrantTypeGrant;
  end;

implementation

uses

  System.SysUtils,
  OAuth2.Entity.AccessToken.Contract,
  OAuth2.Entity.RefreshToken.Contract,
  OAuth2.Entity.Scope.Contract,
  OAuth2.Exception.ServerException;

{ TOAuth2PasswordGrant }

constructor TOAuth2PasswordGrant.Create(AUserRepository: IOAuth2UserRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository);
begin
  SetUserRepository(AUserRepository);
  SetRefreshTokenRepository(ARefreshTokenRepository);
  SetRefreshTokenTTL(60 * 60 * 24 * 30);
end;

function TOAuth2PasswordGrant.GetIdentifier: string;
begin
  Result := 'password';
end;

class function TOAuth2PasswordGrant.New(AUserRepository: IOAuth2UserRepository; ARefreshTokenRepository: IOAuth2RefreshTokenRepository): IOAuth2GrantTypeGrant;
begin
  Result := TOAuth2PasswordGrant.Create(AUserRepository, ARefreshTokenRepository);
end;

function TOAuth2PasswordGrant.RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType;
var
  LClient: IOAuth2ClientEntity;
  LScopes: TArray<IOAuth2ScopeEntity>;
  LUser: IOAuth2UserEntity;
  LFinalizeScopes: TArray<IOAuth2ScopeEntity>;
  LAccessToken: IOAuth2AccessTokenEntity;
  LRefreshToken: IOAuth2RefreshTokenEntity;
begin
  Result := AResponseType;

  LClient := ValidateClient(ARequest);
  LScopes := ValidateScopes(GetRequestParameter('scope', ARequest, GetDefaultScope));
  LUser := ValidateUser(ARequest, LClient);

  LFinalizeScopes := GetScopeRepository.FinalizeScopes(LScopes, GetIdentifier, LClient, LUser.GetIdentifier);

  LAccessToken := IssueAccessToken(AAccessTokenTTL, LClient, LUser.GetIdentifier, LFinalizeScopes);

  AResponseType.SetAccessToken(LAccessToken);

  LRefreshToken := IssueRefreshToken(LAccessToken);

  if LRefreshToken <> nil then
    AResponseType.SetRefreshToken(LRefreshToken);

end;

function TOAuth2PasswordGrant.ValidateUser(ARequest: TWebRequest; AClient: IOAuth2ClientEntity): IOAuth2UserEntity;
var
  LUsername: string;
  LPassword: string;
  LUser: IOAuth2UserEntity;
begin

  LUsername := GetRequestParameter('username', ARequest, EmptyStr);

  if LUsername.IsEmpty then
    raise EOAuth2ServerException.InvalidRequest('username');

  LPassword := GetRequestParameter('password', ARequest, EmptyStr);

  if LPassword.IsEmpty then
    raise EOAuth2ServerException.InvalidRequest('password');

  LUser := GetUserRepository.GetUserEntityByUserCredentials(LUsername, LPassword, GetIdentifier, AClient);

  if LUser = nil then
    raise EOAuth2ServerException.InvalidCredentials;

  Result := LUser;
end;

end.
