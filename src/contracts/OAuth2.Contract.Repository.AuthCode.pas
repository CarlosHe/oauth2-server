unit OAuth2.Contract.Repository.AuthCode;

interface

uses
  OAuth2.Contract.Entity.AuthCode;

type

  IOAuth2AuthCodeRepository = interface
    ['{0B0200DB-6AD7-4BAF-BCDF-F6F693517E98}']
    function GetNewAuthCode: IOAuth2AuthCodeEntity;
    procedure PersistNewAuthCode(AAuthCodeEntity: IOAuth2AuthCodeEntity);
    procedure RevokeAuthCode(ACodeId: string);
    function IsAuthCodeRevoked(ACodeId: string): Boolean;
  end;

implementation

end.
