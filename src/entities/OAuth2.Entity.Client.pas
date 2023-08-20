unit OAuth2.Entity.Client;

interface

uses
  OAuth2.Contract.Entity.Client;

type

  TOAuth2ClientEntity = class(TInterfacedObject, IOAuth2ClientEntity)
  private
    { private declarations }
    FIdentifier: string;
    FName: string;
    FRedirectUri: TArray<string>;
    FIsConfidential: Boolean;
  protected
    { protected declarations }
  public
    { public declarations }
    constructor Create(AIdentifier: string; AName: string; ARedirectUri: TArray<string>; AIsConfidential: Boolean);
    function GetIdentifier: string;
    function GetName: string;
    function GetRedirectUri: TArray<string>;
    function IsConfidential: Boolean;
    class function New(AIdentifier: string; AName: string; ARedirectUri: TArray<string>; AIsConfidential: Boolean): IOAuth2ClientEntity;
  end;

implementation

{ TOAuth2ClientEntity }

constructor TOAuth2ClientEntity.Create(AIdentifier: string; AName: string; ARedirectUri: TArray<string>; AIsConfidential: Boolean);
begin
  FIdentifier := AIdentifier;
  FName := AName;
  FRedirectUri := ARedirectUri;
  FIsConfidential := AIsConfidential;
end;

function TOAuth2ClientEntity.GetIdentifier: string;
begin
  Result := FIdentifier;
end;

function TOAuth2ClientEntity.GetName: string;
begin
  Result := FName;
end;

function TOAuth2ClientEntity.GetRedirectUri: TArray<string>;
begin
  Result := FRedirectUri;
end;

function TOAuth2ClientEntity.IsConfidential: Boolean;
begin
  Result := FIsConfidential;
end;

class function TOAuth2ClientEntity.New(AIdentifier: string; AName: string; ARedirectUri: TArray<string>; AIsConfidential: Boolean): IOAuth2ClientEntity;
begin
  Result := TOAuth2ClientEntity.Create(AIdentifier, AName, ARedirectUri, AIsConfidential);
end;

end.
