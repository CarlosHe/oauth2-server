unit OAuth2.Repository.Scope.Contract;

interface

uses
  OAuth2.Repository.Contract,
  OAuth2.Entity.Client.Contract,
  OAuth2.Entity.Scope.Contract;

type

  IOAuth2ScopeRepository = interface(IOAuth2Repository)
    ['{318F5A92-4B9B-4E40-874F-90EDA87615DA}']
    function GetScopeEntityByIdentifier(AIdentifier: string): IOAuth2ScopeEntity;
    function FinalizeScopes(AScopes: TArray<IOAuth2ScopeEntity>; AGrantType: string; AClientEntity: IOAuth2ClientEntity; const AUserIdentifier: string = ''): TArray<IOAuth2ScopeEntity>;
  end;

implementation

end.
