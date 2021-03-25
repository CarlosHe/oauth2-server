unit OAuth2.Entity.AuthCode.Contract;

interface

uses
  OAuth2.Entity.Token.Contract;

type

  IOAuth2AuthCodeEntity = interface(IOAuth2TokenEntity)
    ['{CCD8B24C-0D39-4F19-8E2C-F02707B150ED}']
    function GetRedirectUri: string;
    procedure SetRedirectUri(AUri: string);
  end;

implementation

end.
