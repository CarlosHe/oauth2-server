unit OAuth2.Entity.AccessToken;

interface

uses
  System.SysUtils,
  OAuth2.Contract.Entity.Scope,
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.AccessToken,
  OAuth2.Entity.Token,
  OAuth2.CryptKey;

type

  TOAuth2AccessTokenEntity = class(TOAuth2TokenEntity, IOAuth2AccessTokenEntity)
  private
    { private declarations }
    FPrivateKey: TOAuth2CryptKey;
  protected
    { protected declarations }
  public
    { public declarations }
    procedure SetPrivateKey(ACryptKey: TOAuth2CryptKey);
    function ToString: string; override;
    class function New: IOAuth2AccessTokenEntity;
  end;

implementation

uses
  System.JSON,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA;

{ TOAuth2AccessTokenEntity }

class function TOAuth2AccessTokenEntity.New: IOAuth2AccessTokenEntity;
begin
  Result := TOAuth2AccessTokenEntity.Create;
end;

procedure TOAuth2AccessTokenEntity.SetPrivateKey(ACryptKey: TOAuth2CryptKey);
begin
  FPrivateKey := ACryptKey;
end;

function TOAuth2AccessTokenEntity.ToString: string;
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
  LCompactToken: string;
  LScopesPayload: TJSONArray;
  I: Integer;
begin
  LCompactToken := '';
  LToken := TJWT.Create;
  try

    LToken.Claims.Audience := GetClient.GetIdentifier;
    LToken.Claims.JWTId := GetIdentifier;
    LToken.Claims.NotBefore := Now;
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Issuer := 'Horse OAuth2';
    LToken.Claims.Expiration := GetExpiryDateTime;
    LToken.Claims.Subject := GetUserIdentifier;
    LScopesPayload := TJSONArray.Create;
    LToken.Claims.JSON.AddPair('scopes', LScopesPayload);

    for I := Low(GetScopes) to High(GetScopes) do
      LScopesPayload.Add(GetScopes[I].GetIdentifier);

    LKey := TJWK.Create(FPrivateKey.GetKey);
    try
      LSigner := TJWS.Create(LToken);
      try
        LSigner.SkipKeyValidation := True;
        LSigner.Sign(LKey, TJOSEAlgorithmId.RS256);
        LCompactToken := LSigner.CompactToken;
      finally
        LSigner.Free;
      end;
    finally
      LKey.Free;
    end;

  finally
    Result := LCompactToken;
    LToken.Free;
  end;
end;

end.
