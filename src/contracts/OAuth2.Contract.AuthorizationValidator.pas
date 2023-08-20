unit OAuth2.Contract.AuthorizationValidator;

interface

uses
  Web.HTTPApp;

type

  IOAuth2AuthorizationValidator = interface
    ['{931FA543-4927-49BF-91FA-BC260ED2164F}']
    function ValidateAuthorization(ARequest: TWebRequest): TWebRequest;
  end;

implementation

end.
