unit OAuth2.Entity.RefreshToken;

interface

uses
  OAuth2.Contract.Entity.RefreshToken,
  OAuth2.Contract.Entity.AccessToken;

type

  TOAuth2RefreshTokenEntity = class(TInterfacedObject, IOAuth2RefreshTokenEntity)
  private
    { private declarations }
    FIdentifier: string;
    FExpiryDateTime: TDateTime;
    FAccessToken: IOAuth2AccessTokenEntity;
  protected
    { protected declarations }
  public
    { public declarations }
    function GetIdentifier: string;
    procedure SetIdentifier(AIdentifier: string);
    function GetExpiryDateTime: TDateTime;
    procedure SetExpiryDateTime(AExpiryDateTime: TDateTime);
    function GetAccessToken: IOAuth2AccessTokenEntity;
    procedure SetAccessToken(AAccessToken: IOAuth2AccessTokenEntity);
    class function New: IOAuth2RefreshTokenEntity;
  end;

implementation

{ TOAuth2RefreshTokenEntity }

function TOAuth2RefreshTokenEntity.GetAccessToken: IOAuth2AccessTokenEntity;
begin
  Result := FAccessToken;
end;

function TOAuth2RefreshTokenEntity.GetExpiryDateTime: TDateTime;
begin
  Result := FExpiryDateTime;
end;

function TOAuth2RefreshTokenEntity.GetIdentifier: string;
begin
  Result := FIdentifier;
end;

class function TOAuth2RefreshTokenEntity.New: IOAuth2RefreshTokenEntity;
begin
  Result := TOAuth2RefreshTokenEntity.Create;
end;

procedure TOAuth2RefreshTokenEntity.SetAccessToken(AAccessToken: IOAuth2AccessTokenEntity);
begin
  FAccessToken := AAccessToken;
end;

procedure TOAuth2RefreshTokenEntity.SetExpiryDateTime(AExpiryDateTime: TDateTime);
begin
  FExpiryDateTime := AExpiryDateTime;
end;

procedure TOAuth2RefreshTokenEntity.SetIdentifier(AIdentifier: string);
begin
  FIdentifier := AIdentifier;
end;

end.
