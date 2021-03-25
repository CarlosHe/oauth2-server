unit OAuth2.Entity.Token.Contract;

interface

uses
  OAuth2.Entity.Client.Contract,
  OAuth2.Entity.Scope.Contract;

type

  IOAuth2TokenEntity = interface
    ['{49556B7D-EC4C-45AD-9A5B-1EBBF1A0644B}']
    function GetIdentifier: string;
    procedure SetIdentifier(AIdentifier: string);
    function GetExpiryDateTime: TDateTime;
    procedure SetExpiryDateTime(AExpiryDateTime: TDateTime);
    function GetUserIdentifier: string;
    procedure SetUserIdentifier(AUserIdentifier: string);
    function GetClient: IOAuth2ClientEntity;
    procedure SetClient(AClientEntity: IOAuth2ClientEntity);
    function GetScopes: TArray<IOAuth2ScopeEntity>;
    procedure AddScope(AScopeEntity: IOAuth2ScopeEntity);
  end;

implementation

end.
