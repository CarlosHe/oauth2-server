unit OAuth2.Grant.GrantType.Contract;

interface

uses
  OAuth2.ResponseType.Contract,
  OAuth2.RequestType.AuthorizationRequest,
  OAuth2.Repository.Client.Contract,
  OAuth2.Repository.AccessToken.Contract,
  OAuth2.Repository.Scope.Contract,
  OAuth2.CryptKey,
  Web.HTTPApp;

type

  IOAuth2GrantTypeGrant = interface
    ['{73258B0C-F1DC-4149-89E5-AC7A73C14FCA}']
    function GetIdentifier: string;
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType;
    function CanRespondToAuthorizationRequest(ARequest: TWebRequest): Boolean;
    function ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest;
    function CompleteAuthorizationRequest(AAuthorizationRequest: TOAuth2AuthorizationRequest): IOAuth2ResponseType;
    function CanRespondToAccessTokenRequest(ARequest: TWebRequest): Boolean;
    procedure SetRefreshTokenTTL(ARefreshTokenTTL: Int64);
    procedure SetClientRepository(AClientRepository: IOAuth2ClientRepository);
    procedure SetAccessTokenRepository(AAccessTokenRepository: IOAuth2AccessTokenRepository);
    procedure SetScopeRepository(AScopeRepository: IOAuth2ScopeRepository);
    procedure SetDefaultScope(ADefaultScope: string);
    procedure SetPrivateKey(APrivateKey: TOAuth2CryptKey);
    procedure SetEncryptionKey(AKey: string);
  end;

implementation

end.
