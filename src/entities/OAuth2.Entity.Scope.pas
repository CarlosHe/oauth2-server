unit OAuth2.Entity.Scope;

interface

uses
  OAuth2.Contract.Entity.Scope;

type

  TOAuth2ScopeEntity = class(TInterfacedObject, IOAuth2ScopeEntity)
  private
    { private declarations }
    FIdentifier: string;
  protected
    { protected declarations }
  public
    { public declarations }
    constructor Create(AIdentifier: string);
    function GetIdentifier: string;
    class function New(AIdentifier: string): IOAuth2ScopeEntity;
  end;

implementation

{ TOAuth2ScopeEntity }

constructor TOAuth2ScopeEntity.Create(AIdentifier: string);
begin
  FIdentifier := AIdentifier;
end;

function TOAuth2ScopeEntity.GetIdentifier: string;
begin
  Result := FIdentifier;
end;

class function TOAuth2ScopeEntity.New(AIdentifier: string): IOAuth2ScopeEntity;
begin
  Result := TOAuth2ScopeEntity.Create(AIdentifier);
end;

end.
