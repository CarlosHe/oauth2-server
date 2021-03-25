unit OAuth2.Repository.User.Contract;

interface

uses
  OAuth2.Repository.Contract,
  OAuth2.Entity.User.Contract,
  OAuth2.Entity.Client.Contract;

type

  IOAuth2UserRepository = interface(IOAuth2Repository)
    ['{C23C59F9-728C-4E04-83D1-4C97EFA96D9E}']
    function GetUserEntityByUserCredentials(AUsername: string; APassword: string; AGrantType: string; AClientEntity: IOAuth2ClientEntity): IOAuth2UserEntity;
  end;

implementation

end.
