unit OAuth2.ResponseType.Contract;

interface

uses
  OAuth2.Entity.AccessToken.Contract,
  OAuth2.Entity.RefreshToken.Contract,
  Web.HTTPApp;

type

  IOAuth2ResponseType = interface
    ['{7511A628-DCD8-45EB-98CC-4B709551D0E3}']
    procedure SetAccessToken(AAccessToken: IOAuth2AccessTokenEntity);
    procedure SetRefreshToken(ARefreshToken: IOAuth2RefreshTokenEntity);
    function GenerateHttpResponse(AResponse: TWebResponse): TWebResponse;
    procedure SetEncryptionKey(const AKey: string = '');
  end;

implementation

end.
