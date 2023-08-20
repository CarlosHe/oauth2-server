unit OAuth2.Grant.AbstractGrant;

interface

uses
  Web.HTTPApp,
  OAuth2.Contract.Grant.GrantType,
  OAuth2.Contract.ResponseType,
  OAuth2.Contract.Repository.Client,
  OAuth2.Contract.Repository.AccessToken,
  OAuth2.Contract.Repository.Scope,
  OAuth2.Contract.Repository.AuthCode,
  OAuth2.Contract.Repository.RefreshToken,
  OAuth2.Contract.Repository.User,
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.Scope,
  OAuth2.Contract.Entity.AccessToken,
  OAuth2.Contract.Entity.AuthCode,
  OAuth2.Contract.Entity.RefreshToken,
  OAuth2.RequestType.AuthorizationRequest,
  OAuth2.CryptKey;

type

  TBasicAuthCredentials = record
  private
    FBasicAuthUser: string;
    FBasicAuthPassword: string;
  public
    constructor Create(ABasicAuthUser: string; ABasicAuthPassword: string);
    function GetBasicAuthUser: string;
    function GetBasicAuthPassword: string;
  end;

  TClientCredentials = record
  private
    FClientId: string;
    FClientSecret: string;
  public
    constructor Create(AClientId: string; AClientSecret: string);
    function GetClientId: string;
    function GetClientSecret: string;
  end;

  TOAuth2AbstractGrant = class(TInterfacedObject, IOAuth2GrantTypeGrant)
  private
    { private declarations }
    FClientRepository: IOAuth2ClientRepository;
    FAccessTokenRepository: IOAuth2AccessTokenRepository;
    FScopeRepository: IOAuth2ScopeRepository;
    FAuthCodeRepository: IOAuth2AuthCodeRepository;
    FRefreshTokenRepository: IOAuth2RefreshTokenRepository;
    FUserRepository: IOAuth2UserRepository;
    FRefreshTokenTTL: Int64;
    FPrivateKey: TOAuth2CryptKey;
    FDefaultScope: string;
    FEncryptionKey: string;
  protected
    const
    MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS = 10;
    SCOPE_DELIMITER_STRING = ' ';
  protected
    { protected declarations }
    procedure ValidateRedirectUri(ARedirectUri: string; AClient: IOAuth2ClientEntity; ARequest: TWebRequest);
    function ValidateClient(ARequest: TWebRequest): IOAuth2ClientEntity;
    function GetBasicAuthCredentials(ARequest: TWebRequest): TBasicAuthCredentials;
    function GetClientCredentials(ARequest: TWebRequest): TClientCredentials;
    function GetClientEntityOrFail(AClientId: string; ARequest: TWebRequest): IOAuth2ClientEntity;
    function ValidateScopes(AScopes: string; const ARedirectUri: string = ''): TArray<IOAuth2ScopeEntity>;
    function GetRequestParameter(AParameter: string; ARequest: TWebRequest; const ADefault: string = ''): string;
    function GetQueryStringParameter(AParameter: string; ARequest: TWebRequest; const ADefault: string = ''): string;
    function GetCookieParameter(AParameter: string; ARequest: TWebRequest; const ADefault: string = ''): string;
    function GenerateUniqueIdentifier(const ALength: Integer = 40): string;
    function IssueAccessToken(AAccessTokenTTL: Int64; AClient: IOAuth2ClientEntity; AUserIdentifier: string; AScopes: TArray<IOAuth2ScopeEntity>): IOAuth2AccessTokenEntity;
    function IssueAuthCode(AAuthCodeTTL: Int64; AClient: IOAuth2ClientEntity; AUserIdentifier: string; ARedirectUri: string; AScopes: TArray<IOAuth2ScopeEntity>)
      : IOAuth2AuthCodeEntity;
    function IssueRefreshToken(AAccessToken: IOAuth2AccessTokenEntity): IOAuth2RefreshTokenEntity;
    function ConvertScopesQueryStringToArray(AScopes: string): TArray<string>;
    function GetEncryptionKey: string;
    function GetScopeRepository: IOAuth2ScopeRepository;
    function GetAuthCodeRepository: IOAuth2AuthCodeRepository;
    function GetUserRepository: IOAuth2UserRepository;
    function GetRefreshTokenRepository: IOAuth2RefreshTokenRepository;
    function GetAccessTokenRepository: IOAuth2AccessTokenRepository;
    function GetDefaultScope: string;
  public
    { public declarations }
    function GetIdentifier: string; virtual;
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType; virtual;
    function CanRespondToAuthorizationRequest(ARequest: TWebRequest): Boolean; virtual;
    function ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest; virtual;
    function CompleteAuthorizationRequest(AAuthorizationRequest: TOAuth2AuthorizationRequest): IOAuth2ResponseType; virtual;
    function CanRespondToAccessTokenRequest(ARequest: TWebRequest): Boolean; virtual;
    procedure SetRefreshTokenTTL(ARefreshTokenTTL: Int64); virtual;
    procedure SetClientRepository(AClientRepository: IOAuth2ClientRepository);
    procedure SetAccessTokenRepository(AAccessTokenRepository: IOAuth2AccessTokenRepository);
    procedure SetScopeRepository(AScopeRepository: IOAuth2ScopeRepository);
    procedure SetRefreshTokenRepository(ARefreshTokenRepository: IOAuth2RefreshTokenRepository); virtual;
    procedure SetAuthCodeRepository(AAuthCodeRepository: IOAuth2AuthCodeRepository);
    procedure SetUserRepository(AUserRepository: IOAuth2UserRepository);
    procedure SetDefaultScope(ADefaultScope: string);
    procedure SetPrivateKey(APrivateKey: TOAuth2CryptKey);
    procedure SetEncryptionKey(AKey: string);
  end;

implementation

uses
  System.Hash,
  System.StrUtils,
  System.NetEncoding,
  System.SysUtils,
  System.DateUtils,
  OAuth2.Exception.ServerException;

{ TOAuth2AbstractGrant }

function TOAuth2AbstractGrant.CanRespondToAccessTokenRequest(ARequest: TWebRequest): Boolean;
begin
  Result := (ARequest.ContentFields.IndexOfName('grant_type') > -1) and (ARequest.ContentFields.Values['grant_type'] = GetIdentifier);
end;

function TOAuth2AbstractGrant.CanRespondToAuthorizationRequest(ARequest: TWebRequest): Boolean;
begin
  Result := False;
end;

function TOAuth2AbstractGrant.CompleteAuthorizationRequest(AAuthorizationRequest: TOAuth2AuthorizationRequest): IOAuth2ResponseType;
begin
  raise Exception.Create('This grant cannot complete an authorization request');
end;

function TOAuth2AbstractGrant.ConvertScopesQueryStringToArray(AScopes: string): TArray<string>;
begin
  Result := AScopes.Split([SCOPE_DELIMITER_STRING]);
end;

function TOAuth2AbstractGrant.GenerateUniqueIdentifier(const ALength: Integer = 40): string;
begin
  Result := THash.GetRandomString(ALength);
end;

function TOAuth2AbstractGrant.GetAccessTokenRepository: IOAuth2AccessTokenRepository;
begin
  Result := FAccessTokenRepository;
end;

function TOAuth2AbstractGrant.GetAuthCodeRepository: IOAuth2AuthCodeRepository;
begin
  Result := FAuthCodeRepository;
end;

function TOAuth2AbstractGrant.GetBasicAuthCredentials(ARequest: TWebRequest): TBasicAuthCredentials;
var
  LAuthorizationHeader: string;
  LDecodedBasicAuth: string;
  LExplodedBasicAuth: TArray<string>;
begin
  LAuthorizationHeader := ARequest.Authorization;
  if LAuthorizationHeader = EmptyStr then
    Exit(TBasicAuthCredentials.Create(EmptyStr, EmptyStr));
  if not LAuthorizationHeader.StartsWith('Basic ') then
    Exit(TBasicAuthCredentials.Create(EmptyStr, EmptyStr));

  try
    LDecodedBasicAuth := TNetEncoding.Base64.Decode(LAuthorizationHeader.Replace('Basic ', ''));
  except
    Exit(TBasicAuthCredentials.Create(EmptyStr, EmptyStr));
  end;

  LExplodedBasicAuth := LDecodedBasicAuth.Split([':']);

  Exit(TBasicAuthCredentials.Create(LExplodedBasicAuth[0], LExplodedBasicAuth[1]));

end;

function TOAuth2AbstractGrant.GetClientCredentials(ARequest: TWebRequest): TClientCredentials;
var
  LBasicAuthCredentials: TBasicAuthCredentials;
  LClientId: string;
  LClientSecret: string;
begin
  LBasicAuthCredentials := GetBasicAuthCredentials(ARequest);
  LClientId := GetRequestParameter('client_id', ARequest, LBasicAuthCredentials.GetBasicAuthUser);

  if LClientId.IsEmpty then
    raise EOAuth2ServerException.InvalidRequest('client_id');

  LClientSecret := GetRequestParameter('client_secret', ARequest, LBasicAuthCredentials.GetBasicAuthPassword);

  Exit(TClientCredentials.Create(LClientId, LClientSecret));
end;

function TOAuth2AbstractGrant.GetClientEntityOrFail(AClientId: string; ARequest: TWebRequest): IOAuth2ClientEntity;
begin
  Result := FClientRepository.GetClientEntity(AClientId);
  if Result = nil then
    raise EOAuth2ServerException.InvalidClient(ARequest);
end;

function TOAuth2AbstractGrant.GetCookieParameter(AParameter: string; ARequest: TWebRequest; const ADefault: string): string;
begin
  if ARequest.CookieFields.IndexOfName(AParameter) = -1 then
    Exit(ADefault);
  Exit(ARequest.CookieFields.Values[AParameter]);
end;

function TOAuth2AbstractGrant.GetDefaultScope: string;
begin
  Result := FDefaultScope;
end;

function TOAuth2AbstractGrant.GetEncryptionKey: string;
begin
  Result := FEncryptionKey;
end;

function TOAuth2AbstractGrant.GetIdentifier: string;
begin

end;

function TOAuth2AbstractGrant.GetQueryStringParameter(AParameter: string; ARequest: TWebRequest; const ADefault: string): string;
begin
  if ARequest.QueryFields.IndexOfName(AParameter) = -1 then
    Exit(ADefault);
  Exit(ARequest.QueryFields.Values[AParameter]);
end;

function TOAuth2AbstractGrant.GetRefreshTokenRepository: IOAuth2RefreshTokenRepository;
begin
  Result := FRefreshTokenRepository;
end;

function TOAuth2AbstractGrant.GetRequestParameter(AParameter: string; ARequest: TWebRequest; const ADefault: string = ''): string;
begin
  if ARequest.ContentFields.IndexOfName(AParameter) = -1 then
    Exit(ADefault);
  Exit(ARequest.ContentFields.Values[AParameter]);
end;

function TOAuth2AbstractGrant.GetScopeRepository: IOAuth2ScopeRepository;
begin
  Result := FScopeRepository;
end;

function TOAuth2AbstractGrant.GetUserRepository: IOAuth2UserRepository;
begin
  Result := FUserRepository;
end;

function TOAuth2AbstractGrant.IssueAccessToken(AAccessTokenTTL: Int64; AClient: IOAuth2ClientEntity; AUserIdentifier: string; AScopes: TArray<IOAuth2ScopeEntity>)
  : IOAuth2AccessTokenEntity;
var
  LMaxGenerationAttempts: Integer;
begin
  LMaxGenerationAttempts := MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
  Result := FAccessTokenRepository.GetNewToken(AClient, AScopes, AUserIdentifier);
  Result.SetExpiryDateTime(IncSecond(Now(), AAccessTokenTTL));
  Result.SetPrivateKey(FPrivateKey);
  while LMaxGenerationAttempts > 0 do
  begin
    Dec(LMaxGenerationAttempts);
    Result.SetIdentifier(GenerateUniqueIdentifier);
    try
      FAccessTokenRepository.PersistNewAccessToken(Result);
      Break;
    except
      on E: Exception do
      begin
        if LMaxGenerationAttempts = 0 then
          raise E
        else
          continue;
      end;
    end;
  end;
end;

function TOAuth2AbstractGrant.IssueAuthCode(AAuthCodeTTL: Int64; AClient: IOAuth2ClientEntity; AUserIdentifier: string; ARedirectUri: string; AScopes: TArray<IOAuth2ScopeEntity>)
  : IOAuth2AuthCodeEntity;
var
  LMaxGenerationAttempts: Integer;
  LScope: IOAuth2ScopeEntity;
begin
  LMaxGenerationAttempts := MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
  Result := FAuthCodeRepository.GetNewAuthCode;
  Result.SetExpiryDateTime(IncSecond(Now(), AAuthCodeTTL));
  Result.SetClient(AClient);
  Result.SetUserIdentifier(AUserIdentifier);
  Result.SetRedirectUri(ARedirectUri);

  for LScope in AScopes do
    Result.AddScope(LScope);

  while LMaxGenerationAttempts > 0 do
  begin
    Dec(LMaxGenerationAttempts);
    Result.SetIdentifier(GenerateUniqueIdentifier);
    try
      FAuthCodeRepository.PersistNewAuthCode(Result);
      Break;
    except
      on E: Exception do
      begin
        if LMaxGenerationAttempts = 0 then
          raise E;
        continue;
      end;
    end;
  end;
end;

function TOAuth2AbstractGrant.IssueRefreshToken(AAccessToken: IOAuth2AccessTokenEntity): IOAuth2RefreshTokenEntity;
var
  LMaxGenerationAttempts: Integer;
begin
  Result := FRefreshTokenRepository.GetNewRefreshToken;
  if Result = nil then
    Exit;

  Result.SetExpiryDateTime(IncSecond(Now(), FRefreshTokenTTL));
  Result.SetAccessToken(AAccessToken);

  LMaxGenerationAttempts := MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
  while LMaxGenerationAttempts > 0 do
  begin
    Dec(LMaxGenerationAttempts);
    Result.SetIdentifier(GenerateUniqueIdentifier);
    try
      FRefreshTokenRepository.PersistNewRefreshToken(Result);
      Break;
    except
      on E: Exception do
      begin
        if LMaxGenerationAttempts = 0 then
          raise E;
        continue;
      end;
    end;
  end;
end;

function TOAuth2AbstractGrant.RespondToAccessTokenRequest(ARequest: TWebRequest; AResponseType: IOAuth2ResponseType; AAccessTokenTTL: Int64): IOAuth2ResponseType;
begin

end;

procedure TOAuth2AbstractGrant.SetAccessTokenRepository(AAccessTokenRepository: IOAuth2AccessTokenRepository);
begin
  FAccessTokenRepository := AAccessTokenRepository;
end;

procedure TOAuth2AbstractGrant.SetAuthCodeRepository(AAuthCodeRepository: IOAuth2AuthCodeRepository);
begin
  FAuthCodeRepository := AAuthCodeRepository;
end;

procedure TOAuth2AbstractGrant.SetClientRepository(AClientRepository: IOAuth2ClientRepository);
begin
  FClientRepository := AClientRepository;
end;

procedure TOAuth2AbstractGrant.SetDefaultScope(ADefaultScope: string);
begin
  FDefaultScope := ADefaultScope;
end;

procedure TOAuth2AbstractGrant.SetEncryptionKey(AKey: string);
begin
  FEncryptionKey := AKey;
end;

procedure TOAuth2AbstractGrant.SetPrivateKey(APrivateKey: TOAuth2CryptKey);
begin
  FPrivateKey := APrivateKey;
end;

procedure TOAuth2AbstractGrant.SetRefreshTokenRepository(ARefreshTokenRepository: IOAuth2RefreshTokenRepository);
begin
  FRefreshTokenRepository := ARefreshTokenRepository;
end;

procedure TOAuth2AbstractGrant.SetRefreshTokenTTL(ARefreshTokenTTL: Int64);
begin
  FRefreshTokenTTL := ARefreshTokenTTL;
end;

procedure TOAuth2AbstractGrant.SetScopeRepository(AScopeRepository: IOAuth2ScopeRepository);
begin
  FScopeRepository := AScopeRepository;
end;

procedure TOAuth2AbstractGrant.SetUserRepository(AUserRepository: IOAuth2UserRepository);
begin
  FUserRepository := AUserRepository;
end;

function TOAuth2AbstractGrant.ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest;
begin
  raise Exception.Create('This grant cannot validate an authorization request');
end;

function TOAuth2AbstractGrant.ValidateClient(ARequest: TWebRequest): IOAuth2ClientEntity;
var
  LClientCredentials: TClientCredentials;
  LClient: IOAuth2ClientEntity;
  LRedirectUri: string;
begin
  LClientCredentials := GetClientCredentials(ARequest);
  if (not FClientRepository.ValidateClient(LClientCredentials.GetClientId, LClientCredentials.GetClientSecret, GetIdentifier)) then
    raise EOAuth2ServerException.InvalidClient(ARequest);

  LClient := GetClientEntityOrFail(LClientCredentials.GetClientId, ARequest);

  LRedirectUri := GetRequestParameter('redirect_uri', ARequest, EmptyStr);

  if not LRedirectUri.IsEmpty then
  begin
    ValidateRedirectUri(LRedirectUri, LClient, ARequest);
  end;

  Exit(LClient)
end;

procedure TOAuth2AbstractGrant.ValidateRedirectUri(ARedirectUri: string; AClient: IOAuth2ClientEntity; ARequest: TWebRequest);
begin
  if (Length(AClient.GetRedirectUri) > 0) and (IndexStr(ARedirectUri, AClient.GetRedirectUri) = -1) then
    raise EOAuth2ServerException.InvalidClient(ARequest);
end;

function TOAuth2AbstractGrant.ValidateScopes(AScopes: string; const ARedirectUri: string): TArray<IOAuth2ScopeEntity>;
var
  LScopes: TArray<string>;
  LScopeItem: string;
  LScope: IOAuth2ScopeEntity;
  LValidScopes: TArray<IOAuth2ScopeEntity>;
  I: Integer;
begin
  Result := [];
  LValidScopes := [];
  LScopes := ConvertScopesQueryStringToArray(AScopes);
  for I := Low(LScopes) to High(LScopes) do
  begin
    LScopeItem := LScopes[I];
    LScope := FScopeRepository.GetScopeEntityByIdentifier(LScopeItem);
    if LScope = nil then
      raise EOAuth2ServerException.InvalidScope(LScopeItem, ARedirectUri);
    LValidScopes := LValidScopes + [LScope];
  end;
  Result := LValidScopes;
end;

{ TBasicAuthCredentials }

function TBasicAuthCredentials.GetBasicAuthPassword: string;
begin
  Result := FBasicAuthPassword;
end;

function TBasicAuthCredentials.GetBasicAuthUser: string;
begin
  Result := FBasicAuthUser;
end;

constructor TBasicAuthCredentials.Create(ABasicAuthUser, ABasicAuthPassword: string);
begin
  FBasicAuthUser := ABasicAuthUser;
  FBasicAuthPassword := ABasicAuthPassword;
end;

{ TClientCredentials }

constructor TClientCredentials.Create(AClientId: string; AClientSecret: string);
begin
  FClientId := AClientId;
  FClientSecret := AClientSecret;
end;

function TClientCredentials.GetClientId: string;
begin
  Result := FClientId;
end;

function TClientCredentials.GetClientSecret: string;
begin
  Result := FClientSecret;
end;

end.
