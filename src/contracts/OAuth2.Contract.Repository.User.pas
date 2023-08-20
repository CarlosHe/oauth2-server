unit OAuth2.Contract.Repository.User;

interface

uses
  OAuth2.Contract.Entity.User,
  OAuth2.Contract.Entity.Client;

type

  IOAuth2UserRepository = interface
    ['{C23C59F9-728C-4E04-83D1-4C97EFA96D9E}']
    function GetUserEntityByUserCredentials(AUsername: string; APassword: string; AGrantType: string; AClientEntity: IOAuth2ClientEntity): IOAuth2UserEntity;
  end;

implementation

end.
