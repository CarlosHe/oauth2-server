unit OAuth2.ResourceServer;

interface

uses
  Web.HTTPApp,
  OAuth2.Contract.Repository.AccessToken,
  OAuth2.Contract.AuthorizationValidator,
  OAuth2.CryptKey;

type

  TOAuth2ResourceServer = class
  private
    { private declarations }
    FAccessTokenRepository: IOAuth2AccessTokenRepository;
    FPublicKey: TOAuth2CryptKey;
    FAuthorizationValidator: IOAuth2AuthorizationValidator;
  protected
    { protected declarations }
  public
    { public declarations }
    constructor Create(AAccessTokenRepository: IOAuth2AccessTokenRepository; APublicKey: TOAuth2CryptKey; const AAuthorizationValidator: IOAuth2AuthorizationValidator = nil);
    function GetAuthorizationValidator: IOAuth2AuthorizationValidator;
    function ValidateAuthenticatedRequest(ARequest: TWebRequest): TWebRequest;
  end;

implementation

uses
  OAuth2.BearerTokenValidator;

{ TOAuth2ResourceServer }

constructor TOAuth2ResourceServer.Create(AAccessTokenRepository: IOAuth2AccessTokenRepository; APublicKey: TOAuth2CryptKey;
  const AAuthorizationValidator: IOAuth2AuthorizationValidator);
begin
  FAccessTokenRepository := AAccessTokenRepository;
  FPublicKey := APublicKey;
  FAuthorizationValidator := AAuthorizationValidator;
end;

function TOAuth2ResourceServer.GetAuthorizationValidator: IOAuth2AuthorizationValidator;
begin
  if FAuthorizationValidator = nil then
    FAuthorizationValidator := TOAuth2BearerTokenValidator.Create(FAccessTokenRepository);

  if FAuthorizationValidator is TOAuth2BearerTokenValidator then
    TOAuth2BearerTokenValidator(FAuthorizationValidator).SetPublicKey(FPublicKey);

  Result := FAuthorizationValidator;
end;

function TOAuth2ResourceServer.ValidateAuthenticatedRequest(ARequest: TWebRequest): TWebRequest;
begin
  Result := GetAuthorizationValidator.ValidateAuthorization(ARequest);
end;

end.
