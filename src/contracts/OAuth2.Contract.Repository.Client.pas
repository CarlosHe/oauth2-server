unit OAuth2.Contract.Repository.Client;

interface

uses
  OAuth2.Contract.Entity.Client;

type

  IOAuth2ClientRepository = interface
    ['{B6D9BC26-7634-4567-92DA-134BB1BB4658}']
    function GetClientEntity(AClientIdentifier: string): IOAuth2ClientEntity;
    function ValidateClient(AClientIdentifier: string; AClientSecret: string; AGrantType: string): Boolean;
  end;

implementation

end.
