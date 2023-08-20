unit OAuth2.Contract.Entity.Client;

interface

type

  IOAuth2ClientEntity = interface
    ['{9E366972-356C-4B90-A68D-CA66889A7350}']
    function GetIdentifier: string;
    function GetName: string;
    function GetRedirectUri: TArray<string>;
    function IsConfidential: Boolean;
  end;

implementation

end.
