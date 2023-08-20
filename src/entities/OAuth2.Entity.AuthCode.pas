unit OAuth2.Entity.AuthCode;

interface

uses
  OAuth2.Contract.Entity.AuthCode,
  OAuth2.Entity.Token;

type

  TOAuth2AuthCodeEntity = class(TOAuth2TokenEntity, IOAuth2AuthCodeEntity)
  private
    { private declarations }
    FRedirectUri: string;
  protected
    { protected declarations }
  public
    { public declarations }
    constructor Create(ARedirectUri: string);
    function GetRedirectUri: string;
    procedure SetRedirectUri(AUri: string);
    class function New(ARedirectUri: string): IOAuth2AuthCodeEntity;
  end;

implementation

{ TOAuth2AuthCodeEntity }

constructor TOAuth2AuthCodeEntity.Create(ARedirectUri: string);
begin
  FRedirectUri := ARedirectUri;
end;

function TOAuth2AuthCodeEntity.GetRedirectUri: string;
begin
  Result := FRedirectUri;
end;

class function TOAuth2AuthCodeEntity.New(ARedirectUri: string): IOAuth2AuthCodeEntity;
begin
  Result := TOAuth2AuthCodeEntity.Create(ARedirectUri);
end;

procedure TOAuth2AuthCodeEntity.SetRedirectUri(AUri: string);
begin
  FRedirectUri := AUri;
end;

end.
