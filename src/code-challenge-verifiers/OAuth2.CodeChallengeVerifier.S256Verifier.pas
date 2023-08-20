unit OAuth2.CodeChallengeVerifier.S256Verifier;

interface

uses
  OAuth2.Contract.CodeChallengeVerifier;

type

  TOAuth2S256Verifier = class(TInterfacedObject, IOAuth2CodeChallengeVerifier)
  private
    { private declarations }
  protected
    { protected declarations }
  public
    { public declarations }
    function GetMethod: string;
    function VerifyCodeChallenge(ACodeVerifier: string; ACodeChallenge: string): Boolean;
  end;

implementation

uses
  System.SysUtils,
  System.NetEncoding,
  System.StrUtils,
  System.Hash;

{ TOAuth2S256Verifier }

function TOAuth2S256Verifier.GetMethod: string;
begin
  Result := 'S256';
end;

function TOAuth2S256Verifier.VerifyCodeChallenge(ACodeVerifier, ACodeChallenge: string): Boolean;
var
  LBase64Encoding: TBase64Encoding;
  LBase64String: string;
begin
  LBase64Encoding := TBase64Encoding.Create(0);
  try
    LBase64String := TEncoding.UTF8.GetString(LBase64Encoding.Encode(THashSHA2.GetHashBytes(ACodeVerifier))).TrimRight(['=']).Replace('+', '-').Replace('/', '_');
    Result := LBase64String = ACodeChallenge;
  finally
    LBase64Encoding.Free;
  end;
end;

end.
