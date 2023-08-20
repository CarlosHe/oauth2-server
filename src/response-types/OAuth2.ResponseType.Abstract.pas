unit OAuth2.ResponseType.Abstract;

interface

uses
  Web.HTTPApp,
  OAuth2.Contract.ResponseType,
  OAuth2.Contract.Entity.AccessToken,
  OAuth2.Contract.Entity.RefreshToken,
  OAuth2.CryptKey;

type

  TOAuth2AbstractResponseType = class abstract(TInterfacedObject, IOAuth2ResponseType)
  private
    { private declarations }
    FAccessToken: IOAuth2AccessTokenEntity;
    FRefreshToken: IOAuth2RefreshTokenEntity;
    FEncryptionKey: string;
    FPrivateKey: TOAuth2CryptKey;
  protected
    { protected declarations }
    property AccessToken: IOAuth2AccessTokenEntity read FAccessToken;
    property RefreshToken: IOAuth2RefreshTokenEntity read FRefreshToken;
    property EncryptionKey: string read FEncryptionKey;
    property PrivateKey: TOAuth2CryptKey read FPrivateKey;
  public
    { public declarations }
    procedure SetAccessToken(AAccessToken: IOAuth2AccessTokenEntity);
    procedure SetRefreshToken(ARefreshToken: IOAuth2RefreshTokenEntity);
    function GenerateHttpResponse(AResponse: TWebResponse): TWebResponse; virtual;
    procedure SetEncryptionKey(const AKey: string = '');
    procedure SetPrivateKey(ACryptKey: TOAuth2CryptKey);
  end;

implementation

uses
  System.SysUtils;

{ TOAuth2AbstractResponseType }

function TOAuth2AbstractResponseType.GenerateHttpResponse(AResponse: TWebResponse): TWebResponse;
begin
  Result := AResponse;
end;

procedure TOAuth2AbstractResponseType.SetAccessToken(AAccessToken: IOAuth2AccessTokenEntity);
begin
  FAccessToken := AAccessToken;
end;

procedure TOAuth2AbstractResponseType.SetEncryptionKey(const AKey: string);
begin
  FEncryptionKey := AKey;
end;

procedure TOAuth2AbstractResponseType.SetPrivateKey(ACryptKey: TOAuth2CryptKey);
begin
  FPrivateKey := ACryptKey;
end;

procedure TOAuth2AbstractResponseType.SetRefreshToken(ARefreshToken: IOAuth2RefreshTokenEntity);
begin
  FRefreshToken := ARefreshToken;
end;

end.
