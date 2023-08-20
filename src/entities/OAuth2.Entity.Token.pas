unit OAuth2.Entity.Token;

interface

uses
  System.SysUtils,
  OAuth2.Contract.Entity.Scope,
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.Token;

type

  TOAuth2TokenEntity = class(TInterfacedObject, IOAuth2TokenEntity)
  private
    { private declarations }
    FIdentifier: string;
    FExpiryDateTime: TDateTime;
    FUserIdentifier: string;
    FClient: IOAuth2ClientEntity;
    FScopes: TArray<IOAuth2ScopeEntity>;
  protected
    { protected declarations }
  public
    { public declarations }
    function GetIdentifier: string;
    procedure SetIdentifier(AIdentifier: string);
    function GetExpiryDateTime: TDateTime;
    procedure SetExpiryDateTime(AExpiryDateTime: TDateTime);
    function GetUserIdentifier: string;
    procedure SetUserIdentifier(AUserIdentifier: string);
    function GetClient: IOAuth2ClientEntity;
    procedure SetClient(AClientEntity: IOAuth2ClientEntity);
    function GetScopes: TArray<IOAuth2ScopeEntity>;
    procedure AddScope(AScopeEntity: IOAuth2ScopeEntity);
    class function New: IOAuth2TokenEntity;
  end;

implementation

{ TOAuth2TokenEntity }

procedure TOAuth2TokenEntity.AddScope(AScopeEntity: IOAuth2ScopeEntity);
begin
  FScopes := FScopes + [AScopeEntity];
end;

function TOAuth2TokenEntity.GetClient: IOAuth2ClientEntity;
begin
  Result := FClient;
end;

function TOAuth2TokenEntity.GetExpiryDateTime: TDateTime;
begin
  Result := FExpiryDateTime;
end;

function TOAuth2TokenEntity.GetIdentifier: string;
begin
  Result := FIdentifier;
end;

function TOAuth2TokenEntity.GetScopes: TArray<IOAuth2ScopeEntity>;
begin
  Result := FScopes;
end;

function TOAuth2TokenEntity.GetUserIdentifier: string;
begin
  Result := FUserIdentifier;
end;

class function TOAuth2TokenEntity.New: IOAuth2TokenEntity;
begin
  Result := TOAuth2TokenEntity.Create;
end;

procedure TOAuth2TokenEntity.SetClient(AClientEntity: IOAuth2ClientEntity);
begin
  FClient := AClientEntity;
end;

procedure TOAuth2TokenEntity.SetExpiryDateTime(AExpiryDateTime: TDateTime);
begin
  FExpiryDateTime := AExpiryDateTime;
end;

procedure TOAuth2TokenEntity.SetIdentifier(AIdentifier: string);
begin
  FIdentifier := AIdentifier;
end;

procedure TOAuth2TokenEntity.SetUserIdentifier(AUserIdentifier: string);
begin
  FUserIdentifier := AUserIdentifier;
end;

end.
