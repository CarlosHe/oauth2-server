unit OAuth2.Entity.User;

interface

uses
  OAuth2.Contract.Entity.User;

type

  TOAuth2UserEntity = class(TInterfacedObject, IOAuth2UserEntity)
  private
    { private declarations }
    FIdentifier: string;
  protected
    { protected declarations }
  public
    { public declarations }
    constructor Create(AIdentifier: string);
    function GetIdentifier: string;
    class function New(AIdentifier: string): IOAuth2UserEntity;
  end;

implementation

{ TOAuth2UserEntity }

constructor TOAuth2UserEntity.Create(AIdentifier: string);
begin
  FIdentifier := AIdentifier;
end;

function TOAuth2UserEntity.GetIdentifier: string;
begin
  Result := FIdentifier;
end;

class function TOAuth2UserEntity.New(AIdentifier: string): IOAuth2UserEntity;
begin
  Result := TOAuth2UserEntity.Create(AIdentifier);
end;

end.
