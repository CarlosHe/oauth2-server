unit OAuth2.CodeChallengeVerifier.PlainVerifier;

interface

uses
  OAuth2.Contract.CodeChallengeVerifier;

type

  TOAuth2PlainVerifier = class(TInterfacedObject, IOAuth2CodeChallengeVerifier)
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
  System.Hash;

{ TOAuth2PlainVerifier }

function TOAuth2PlainVerifier.GetMethod: string;
begin
  Result := 'plain';
end;

function TOAuth2PlainVerifier.VerifyCodeChallenge(ACodeVerifier, ACodeChallenge: string): Boolean;
begin
  Result := ACodeVerifier = ACodeChallenge;
end;

end.
