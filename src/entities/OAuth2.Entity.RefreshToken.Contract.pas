unit OAuth2.Entity.RefreshToken.Contract;

interface

uses
  OAuth2.Entity.AccessToken.Contract;

type

  IOAuth2RefreshTokenEntity = interface
    ['{A0E150DB-9543-4D02-A220-084518528DF4}']
    function GetIdentifier: string;
    procedure SetIdentifier(AIdentifier: string);
    function GetExpiryDateTime: TDateTime;
    procedure SetExpiryDateTime(AExpiryDateTime: TDateTime);
    function GetAccessToken: IOAuth2AccessTokenEntity;
    procedure SetAccessToken(AAccessToken: IOAuth2AccessTokenEntity);
  end;

implementation

end.
