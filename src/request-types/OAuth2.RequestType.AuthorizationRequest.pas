unit OAuth2.RequestType.AuthorizationRequest;

interface

uses
  System.JSON,
  System.Generics.Collections,
  OAuth2.Contract.Entity.Client,
  OAuth2.Contract.Entity.User,
  OAuth2.Contract.Entity.Scope;

type

  TOAuth2AuthorizationRequest = class
  private
    { private declarations }
    FGrantTypeId: string;
    FClient: IOAuth2ClientEntity;
    FUser: IOAuth2UserEntity;
    FScopes: TArray<IOAuth2ScopeEntity>;
    FAuthorizationApproved: Boolean;
    FRedirectUri: string;
    FState: string;
    FCodeChallenge: string;
    FCodeChallengeMethod: string;
  protected
    { protected declarations }
  public
    { public declarations }
    function GetGrantTypeId: string;
    procedure SetGrantTypeId(AGrantTypeId: string);
    function GetClient: IOAuth2ClientEntity;
    procedure SetClient(AClient: IOAuth2ClientEntity);
    function GetUser: IOAuth2UserEntity;
    procedure SetUser(AUser: IOAuth2UserEntity);
    function GetScopes: TArray<IOAuth2ScopeEntity>;
    procedure SetScopes(AScopes: TArray<IOAuth2ScopeEntity>);
    function IsAuthorizationApproved: Boolean;
    procedure SetAuthorizationApproved(AAuthorizationApproved: Boolean);
    function GetRedirectUri: string;
    procedure SetRedirectUri(ARedirectUri: string);
    function GetState: string;
    procedure SetState(AState: string);
    function GetCodeChallenge: string;
    procedure SetCodeChallenge(ACodeChallenge: string);
    function GetCodeChallengeMethod: string;
    procedure SetCodeChallengeMethod(ACodeChallengeMethod: string);
    function ToJSON: TJSONObject;
    procedure FromJSON(AJSON: TJSONObject);
  end;

implementation

uses
  OAuth2.Entity.Client,
  OAuth2.Entity.Scope;

{ TOAuth2AuthorizationRequest }

procedure TOAuth2AuthorizationRequest.FromJSON(AJSON: TJSONObject);
var
  LJSONObjectAuthRequest: TJSONObject;
  LJSONObjectClient: TJSONObject;
  LJSONArrayClientRedirectUri: TJSONArray;
  LJSONArrayScopes: TJSONArray;
  LClientId: string;
  LClientName: string;
  LClientRedirectUri: TArray<string>;
  LClientIsConfidential: Boolean;
  I: Integer;
begin
  LJSONObjectAuthRequest := AJSON.Clone as TJSONObject;
  try
    if LJSONObjectAuthRequest = nil then
      Exit;

    LJSONObjectAuthRequest.TryGetValue<string>('grant_type_id', FGrantTypeId);
    LJSONObjectAuthRequest.TryGetValue<TJSONObject>('client', LJSONObjectClient);
    if LJSONObjectClient <> nil then
    begin
      LJSONObjectClient.TryGetValue<string>('id', LClientId);
      LJSONObjectClient.TryGetValue<string>('name', LClientName);
      LJSONObjectClient.TryGetValue<TJSONArray>('redirect_uri', LJSONArrayClientRedirectUri);
      LJSONObjectClient.TryGetValue<Boolean>('is_confidential', LClientIsConfidential);
      LClientRedirectUri := [];
      for I := 0 to Pred(LJSONArrayClientRedirectUri.Count) do
        LClientRedirectUri := LClientRedirectUri + [LJSONArrayClientRedirectUri.Items[I].Value];
      FClient := TOAuth2ClientEntity.New(LClientId, LClientName, LClientRedirectUri, LClientIsConfidential)
    end;
    LJSONObjectAuthRequest.TryGetValue<TJSONArray>('scopes', LJSONArrayScopes);
    if LJSONArrayScopes <> nil then
    begin
      FScopes := [];
      for I := 0 to Pred(LJSONArrayScopes.Count) do
        FScopes := FScopes + [TOAuth2ScopeEntity.New(LJSONArrayScopes.Items[I].Value)];
    end;
    LJSONObjectAuthRequest.TryGetValue<Boolean>('authorization_approved', FAuthorizationApproved);
    LJSONObjectAuthRequest.TryGetValue<string>('redirect_uri', FRedirectUri);
    LJSONObjectAuthRequest.TryGetValue<string>('state', FState);
    LJSONObjectAuthRequest.TryGetValue<string>('code_challenge', FCodeChallenge);
    LJSONObjectAuthRequest.TryGetValue<string>('code_challenge_method', FCodeChallengeMethod);
  finally
    LJSONObjectAuthRequest.Free;
  end;
end;

function TOAuth2AuthorizationRequest.GetClient: IOAuth2ClientEntity;
begin
  Result := FClient;
end;

function TOAuth2AuthorizationRequest.GetCodeChallenge: string;
begin
  Result := FCodeChallenge;
end;

function TOAuth2AuthorizationRequest.GetCodeChallengeMethod: string;
begin
  Result := FCodeChallengeMethod;
end;

function TOAuth2AuthorizationRequest.GetGrantTypeId: string;
begin
  Result := FGrantTypeId;
end;

function TOAuth2AuthorizationRequest.GetRedirectUri: string;
begin
  Result := FRedirectUri;
end;

function TOAuth2AuthorizationRequest.GetScopes: TArray<IOAuth2ScopeEntity>;
begin
  Result := FScopes;
end;

function TOAuth2AuthorizationRequest.GetState: string;
begin
  Result := FState;
end;

function TOAuth2AuthorizationRequest.GetUser: IOAuth2UserEntity;
begin
  Result := FUser;
end;

function TOAuth2AuthorizationRequest.IsAuthorizationApproved: Boolean;
begin
  Result := FAuthorizationApproved;
end;

procedure TOAuth2AuthorizationRequest.SetAuthorizationApproved(AAuthorizationApproved: Boolean);
begin
  FAuthorizationApproved := AAuthorizationApproved;
end;

procedure TOAuth2AuthorizationRequest.SetClient(AClient: IOAuth2ClientEntity);
begin
  FClient := AClient;
end;

procedure TOAuth2AuthorizationRequest.SetCodeChallenge(ACodeChallenge: string);
begin
  FCodeChallenge := ACodeChallenge;
end;

procedure TOAuth2AuthorizationRequest.SetCodeChallengeMethod(ACodeChallengeMethod: string);
begin
  FCodeChallengeMethod := ACodeChallengeMethod;
end;

procedure TOAuth2AuthorizationRequest.SetGrantTypeId(AGrantTypeId: string);
begin
  FGrantTypeId := AGrantTypeId;
end;

procedure TOAuth2AuthorizationRequest.SetRedirectUri(ARedirectUri: string);
begin
  FRedirectUri := ARedirectUri;
end;

procedure TOAuth2AuthorizationRequest.SetScopes(AScopes: TArray<IOAuth2ScopeEntity>);
begin
  FScopes := AScopes;
end;

procedure TOAuth2AuthorizationRequest.SetState(AState: string);
begin
  FState := AState;
end;

procedure TOAuth2AuthorizationRequest.SetUser(AUser: IOAuth2UserEntity);
begin
  FUser := AUser;
end;

function TOAuth2AuthorizationRequest.ToJSON: TJSONObject;
var
  LJSONObjectAuthRequest: TJSONObject;
  LJSONObjectClient: TJSONObject;
  LJSONArrayClientRedirectUri: TJSONArray;
  LJSONArrayScopes: TJSONArray;
  I: Integer;
begin
  LJSONObjectAuthRequest := TJSONObject.Create;
  Result := LJSONObjectAuthRequest;
  LJSONObjectAuthRequest.AddPair('grant_type_id', FGrantTypeId);
  LJSONObjectClient := TJSONObject.Create;
  LJSONObjectAuthRequest.AddPair('client', LJSONObjectClient);
  LJSONObjectClient.AddPair('id', FClient.GetIdentifier);
  LJSONObjectClient.AddPair('name', FClient.GetName);
  LJSONArrayClientRedirectUri := TJSONArray.Create;
  LJSONObjectClient.AddPair('redirect_uri', LJSONArrayClientRedirectUri);
  for I := Low(FClient.GetRedirectUri) to High(FClient.GetRedirectUri) do
    LJSONArrayClientRedirectUri.Add(FClient.GetRedirectUri[I]);
  LJSONObjectClient.AddPair('is_confidential', TJSONBool.Create(FClient.IsConfidential));
  if FUser <> nil then
  begin
    LJSONObjectAuthRequest.AddPair('user_id', FUser.GetIdentifier);
  end;
  LJSONArrayScopes := TJSONArray.Create;
  LJSONObjectAuthRequest.AddPair('scopes', LJSONArrayScopes);
  for I := Low(FScopes) to High(FScopes) do
    LJSONArrayScopes.Add(FScopes[I].GetIdentifier);
  LJSONObjectAuthRequest.AddPair('authorization_approved', TJSONBool.Create(FAuthorizationApproved));
  LJSONObjectAuthRequest.AddPair('redirect_uri', FRedirectUri);
  LJSONObjectAuthRequest.AddPair('state', FState);
  LJSONObjectAuthRequest.AddPair('code_challenge', FCodeChallenge);
  LJSONObjectAuthRequest.AddPair('code_challenge_method', FCodeChallengeMethod);
end;

end.
