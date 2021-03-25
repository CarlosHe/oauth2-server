unit OAuth2.Repository.AuthCode.Contract;

interface

uses
  OAuth2.Repository.Contract,
  OAuth2.Entity.AuthCode.Contract;

type

  IOAuth2AuthCodeRepository = interface(IOAuth2Repository)
    ['{0B0200DB-6AD7-4BAF-BCDF-F6F693517E98}']
    function GetNewAuthCode: IOAuth2AuthCodeEntity;
    procedure PersistNewAuthCode(AAuthCodeEntity: IOAuth2AuthCodeEntity);
    procedure RevokeAuthCode(ACodeId: string);
    function IsAuthCodeRevoked(ACodeId: string): Boolean;
  end;

implementation

end.
