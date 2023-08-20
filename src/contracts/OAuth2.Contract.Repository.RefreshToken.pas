unit OAuth2.Contract.Repository.RefreshToken;

interface

uses
  OAuth2.Contract.Entity.RefreshToken;

type

  IOAuth2RefreshTokenRepository = interface
    ['{3AF5AB3C-2331-4545-AFDF-569BD048B2FC}']
    function GetNewRefreshToken: IOAuth2RefreshTokenEntity;
    procedure PersistNewRefreshToken(ARefreshTokenEntity: IOAuth2RefreshTokenEntity);
    procedure RevokeRefreshToken(ATokenId: string);
    function IsRefreshTokenRevoked(ATokenId: string): Boolean;
  end;

implementation

end.
