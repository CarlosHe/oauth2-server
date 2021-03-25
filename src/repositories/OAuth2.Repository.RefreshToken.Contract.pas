unit OAuth2.Repository.RefreshToken.Contract;

interface

uses
  OAuth2.Repository.Contract,
  OAuth2.Entity.RefreshToken.Contract;

type

  IOAuth2RefreshTokenRepository = interface(IOAuth2Repository)
    ['{3AF5AB3C-2331-4545-AFDF-569BD048B2FC}']
    function GetNewRefreshToken: IOAuth2RefreshTokenEntity;
    procedure PersistNewRefreshToken(ARefreshTokenEntity: IOAuth2RefreshTokenEntity);
    procedure RevokeRefreshToken(ATokenId: string);
    function IsRefreshTokenRevoked(ATokenId: string): Boolean;
  end;

implementation

end.
