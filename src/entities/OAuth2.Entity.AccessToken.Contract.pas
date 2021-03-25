unit OAuth2.Entity.AccessToken.Contract;

interface

uses
  OAuth2.Entity.Token.Contract,
  OAuth2.CryptKey;

type

  IOAuth2AccessTokenEntity = interface(IOAuth2TokenEntity)
    ['{CC02702E-7AD3-496E-BFAF-89A9BA54DD44}']
    procedure SetPrivateKey(ACryptKey: TOAuth2CryptKey);
    function ToString: string;
  end;

implementation

end.
