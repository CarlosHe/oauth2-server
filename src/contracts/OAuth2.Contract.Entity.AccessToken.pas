unit OAuth2.Contract.Entity.AccessToken;

interface

uses
  OAuth2.Contract.Entity.Token,
  OAuth2.CryptKey;

type

  IOAuth2AccessTokenEntity = interface(IOAuth2TokenEntity)
    ['{CC02702E-7AD3-496E-BFAF-89A9BA54DD44}']
    procedure SetPrivateKey(ACryptKey: TOAuth2CryptKey);
    function ToString: string;
  end;

implementation

end.
