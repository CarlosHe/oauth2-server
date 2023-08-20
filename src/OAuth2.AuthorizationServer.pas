unit OAuth2.AuthorizationServer;

interface

uses
  Web.HTTPApp,
  System.Generics.Collections,
  OAuth2.Contract.Grant.GrantType,
  OAuth2.Contract.ResponseType,
  OAuth2.Contract.Repository.Client,
  OAuth2.Contract.Repository.AccessToken,
  OAuth2.Contract.Repository.Scope,
  OAuth2.RequestType.AuthorizationRequest,
  OAuth2.CryptKey;

type

  TOAuth2AuthorizationServer = class
  private
    { private declarations }
    FEnabledGrantTypes: TDictionary<string, IOAuth2GrantTypeGrant>;
    FGrantTypeAccessTokenTTL: TDictionary<string, Int64>;
    FPrivateKey: TOAuth2CryptKey;
    FResponseType: IOAuth2ResponseType;
    FClientRepository: IOAuth2ClientRepository;
    FAccessTokenRepository: IOAuth2AccessTokenRepository;
    FScopeRepository: IOAuth2ScopeRepository;
    FEncryptionKey: string;
    FDefaultScope: string;
  protected
    { protected declarations }
    function GetResponseType: IOAuth2ResponseType;
  public
    { public declarations }
    constructor Create(
      AClientRepository: IOAuth2ClientRepository;
      AAccessTokenRepository: IOAuth2AccessTokenRepository;
      AScopeRepository: IOAuth2ScopeRepository;
      APrivateKey: TOAuth2CryptKey;
      AEncryptionKey: string;
      const AResponseType: IOAuth2ResponseType = nil
      );
    destructor Destroy; override;
    procedure EnableGrantType(AGrantType: IOAuth2GrantTypeGrant; const AAccessTokenTTL: Int64 = -1);
    function ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest;
    function CompleteAuthorizationRequest(AAuthRequest: TOAuth2AuthorizationRequest; AResponse: TWebResponse): TWebResponse;
    function RespondToAccessTokenRequest(ARequest: TWebRequest; AResponse: TWebResponse): TWebResponse;
    procedure SetDefaultScope(ADefaultScope: string);
  end;

implementation

uses
  System.JSON,
  OAuth2.ResponseType.BearerTokenResponse,
  OAuth2.Exception.ServerException,
  OAuth2.ResponseType.Abstract;

{ TOAuth2AuthorizationServer }

function TOAuth2AuthorizationServer.CompleteAuthorizationRequest(AAuthRequest: TOAuth2AuthorizationRequest; AResponse: TWebResponse): TWebResponse;
begin
  Result := FEnabledGrantTypes[AAuthRequest.GetGrantTypeId]
    .CompleteAuthorizationRequest(AAuthRequest)
    .GenerateHttpResponse(AResponse);
end;

constructor TOAuth2AuthorizationServer.Create(AClientRepository: IOAuth2ClientRepository; AAccessTokenRepository: IOAuth2AccessTokenRepository;
  AScopeRepository: IOAuth2ScopeRepository; APrivateKey: TOAuth2CryptKey; AEncryptionKey: string; const AResponseType: IOAuth2ResponseType);
begin
  FEnabledGrantTypes := TDictionary<string, IOAuth2GrantTypeGrant>.Create;
  FGrantTypeAccessTokenTTL := TDictionary<string, Int64>.Create;
  FClientRepository := AClientRepository;
  FAccessTokenRepository := AAccessTokenRepository;
  FScopeRepository := AScopeRepository;
  FPrivateKey := APrivateKey;
  FEncryptionKey := AEncryptionKey;
  if AResponseType = nil then
    FResponseType := TOAuth2BearerTokenResponse.Create
  else
    FResponseType := AResponseType;
end;

destructor TOAuth2AuthorizationServer.Destroy;
begin
  FGrantTypeAccessTokenTTL.Free;
  FEnabledGrantTypes.Free;
  inherited;
end;

procedure TOAuth2AuthorizationServer.EnableGrantType(AGrantType: IOAuth2GrantTypeGrant; const AAccessTokenTTL: Int64);
begin
  AGrantType.SetAccessTokenRepository(FAccessTokenRepository);
  AGrantType.SetClientRepository(FClientRepository);
  AGrantType.SetScopeRepository(FScopeRepository);
  AGrantType.SetDefaultScope(FDefaultScope);
  AGrantType.SetPrivateKey(FPrivateKey);
  AGrantType.SetEncryptionKey(FEncryptionKey);
  FEnabledGrantTypes.AddOrSetValue(AGrantType.GetIdentifier, AGrantType);
  FGrantTypeAccessTokenTTL.AddOrSetValue(AGrantType.GetIdentifier, AAccessTokenTTL);
end;

function TOAuth2AuthorizationServer.GetResponseType: IOAuth2ResponseType;
begin
  Result := FResponseType;
  if Result is TOAuth2AbstractResponseType then
    TOAuth2AbstractResponseType(Result).SetPrivateKey(FPrivateKey);
  Result.SetEncryptionKey(FEncryptionKey);
end;

function TOAuth2AuthorizationServer.RespondToAccessTokenRequest(ARequest: TWebRequest; AResponse: TWebResponse): TWebResponse;
var
  LGrantTypeIdentifier: string;
  LGrantType: IOAuth2GrantTypeGrant;
  LTokenResponse: IOAuth2ResponseType;
begin
  Result := AResponse;
  for LGrantTypeIdentifier in FEnabledGrantTypes.Keys do
  begin
    LGrantType := FEnabledGrantTypes.Items[LGrantTypeIdentifier];
    if not LGrantType.CanRespondToAccessTokenRequest(ARequest) then
      Continue;
    LTokenResponse := LGrantType.RespondToAccessTokenRequest(
      ARequest,
      GetResponseType,
      FGrantTypeAccessTokenTTL.Items[LGrantType.GetIdentifier]
      );
    if LTokenResponse <> nil then
      LTokenResponse.GenerateHttpResponse(AResponse);
    Exit;
  end;
  raise EOAuth2ServerException.UnsupportedGrantType;
end;

procedure TOAuth2AuthorizationServer.SetDefaultScope(ADefaultScope: string);
begin
  FDefaultScope := ADefaultScope;
end;

function TOAuth2AuthorizationServer.ValidateAuthorizationRequest(ARequest: TWebRequest): TOAuth2AuthorizationRequest;
var
  LGrantTypeIdentifier: string;
  LGrantType: IOAuth2GrantTypeGrant;
begin
  for LGrantTypeIdentifier in FEnabledGrantTypes.Keys do
  begin
    LGrantType := FEnabledGrantTypes.Items[LGrantTypeIdentifier];
    if LGrantType.CanRespondToAuthorizationRequest(ARequest) then
    begin
      Exit(LGrantType.ValidateAuthorizationRequest(ARequest))
    end;
  end;
  raise EOAuth2ServerException.UnsupportedGrantType;
end;

end.
