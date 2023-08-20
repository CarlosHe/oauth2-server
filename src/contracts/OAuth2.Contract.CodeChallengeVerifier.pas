unit OAuth2.Contract.CodeChallengeVerifier;

interface

type

  IOAuth2CodeChallengeVerifier = interface
    ['{620B42C3-F80D-451A-9DCF-C217B440F57C}']
    function GetMethod: string;
    function VerifyCodeChallenge(ACodeVerifier: string; ACodeChallenge: string): Boolean;
  end;

implementation

end.
