unit OAuth2.Contract.Repository.Scope;

interface

uses
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.Scope;

type

  IOAuth2ScopeRepository = interface
    ['{318F5A92-4B9B-4E40-874F-90EDA87615DA}']
    function GetScopeEntityByIdentifier(AIdentifier: string): IOAuth2ScopeEntity;
    function FinalizeScopes(AScopes: TArray<IOAuth2ScopeEntity>; AGrantType: string; AClientEntity: IOAuth2ClientEntity; const AUserIdentifier: string = ''): TArray<IOAuth2ScopeEntity>;
  end;

implementation

end.
