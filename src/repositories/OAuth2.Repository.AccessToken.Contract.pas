unit OAuth2.Repository.AccessToken.Contract;

interface

uses
  OAuth2.Repository.Contract,
  OAuth2.Entity.Client.Contract,
  OAuth2.Entity.Scope.Contract,
  OAuth2.Entity.AccessToken.Contract;

type

  IOAuth2AccessTokenRepository = interface(IOAuth2Repository)
    ['{C63B4BC6-3959-41BC-8016-5FE3A70EF122}']
    function GetNewToken(AClientEntity: IOAuth2ClientEntity; AScopes: TArray<IOAuth2ScopeEntity>; const AUserIdentifier: string = ''): IOAuth2AccessTokenEntity;
    procedure PersistNewAccessToken(AAccessTokenEntity: IOAuth2AccessTokenEntity);
    procedure RevokeAccessToken(ATokenId: string);
    function IsAccessTokenRevoked(ATokenId: string): Boolean;
  end;

implementation

end.
