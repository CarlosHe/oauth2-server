unit OAuth2.Contract.Repository.AccessToken;

interface

uses
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.Scope,
  OAuth2.Contract.Entity.AccessToken;

type

  IOAuth2AccessTokenRepository = interface
    ['{C63B4BC6-3959-41BC-8016-5FE3A70EF122}']
    function GetNewToken(AClientEntity: IOAuth2ClientEntity; AScopes: TArray<IOAuth2ScopeEntity>; const AUserIdentifier: string = ''): IOAuth2AccessTokenEntity;
    procedure PersistNewAccessToken(AAccessTokenEntity: IOAuth2AccessTokenEntity);
    procedure RevokeAccessToken(ATokenId: string);
    function IsAccessTokenRevoked(ATokenId: string): Boolean;
  end;

implementation

end.
