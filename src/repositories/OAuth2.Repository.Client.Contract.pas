unit OAuth2.Repository.Client.Contract;

interface

uses
  OAuth2.Repository.Contract,
  OAuth2.Entity.Client.Contract;

type

  IOAuth2ClientRepository = interface(IOAuth2Repository)
    ['{B6D9BC26-7634-4567-92DA-134BB1BB4658}']
    function GetClientEntity(AClientIdentifier: string): IOAuth2ClientEntity;
    function ValidateClient(AClientIdentifier: string; AClientSecret: string; AGrantType: string): Boolean;
  end;

implementation

end.
