unit OAuth2.Exception.ServerException;

interface

uses
  System.Generics.Collections,
  System.JSON,
  System.SysUtils,
  Web.HTTPApp;

type

  EOAuth2ServerException = class(Exception)
  private
    { private declarations }
    FHttpStatusCode: Integer;
    FErrorType: string;
    FHint: string;
    FRedirectUri: string;
    FPayload: TJSONObject;
    FRequest: TWebRequest;
  protected
    { protected declarations }
  public
    { public declarations }
    constructor Create(const AMessage: string; ACode: Integer; AErrorType: string; AHttpStatusCode: Integer; AHint: string; ARedirectUri: string);
    destructor Destroy; override;
    function GetHttpStatusCode: Integer;
    function GetErrorType: string;
    function GetHint: string;
    function GetRedirectUri: string;
    function GetPayload: TJSONObject;
    procedure SetServerRequest(ARequest: TWebRequest);
    function GenerateHttpResponse(AResponse: TWebResponse; const AUseFragment: Boolean = False): TWebResponse;
    class function InvalidRequest(AParameter: string; const AHint: string = ''): EOAuth2ServerException;
    class function InvalidClient(ARequest: TWebRequest): EOAuth2ServerException;
    class function InvalidScope(AScope: string; const ARedirectUri: string = ''): EOAuth2ServerException;
    class function InvalidGrant(const AHint: string = ''): EOAuth2ServerException;
    class function InvalidRefreshToken(const AHint: string = ''): EOAuth2ServerException;
    class function InvalidCredentials: EOAuth2ServerException;
    class function ServerError(const AHint: string = ''): EOAuth2ServerException;
    class function AccessDenied(const AHint: string = ''; const ARedirectUri: string = ''): EOAuth2ServerException;
    class function UnsupportedGrantType: EOAuth2ServerException;
  end;

implementation

{ EOAuth2ServerException }

class function EOAuth2ServerException.AccessDenied(const AHint, ARedirectUri: string): EOAuth2ServerException;
begin
  Result := Create(
    'The resource owner or authorization server denied the request',
    9, 'access_denied', 401, AHint, ARedirectUri);
end;

constructor EOAuth2ServerException.Create(const AMessage: string; ACode: Integer; AErrorType: string; AHttpStatusCode: Integer; AHint, ARedirectUri: string);
begin
  inherited Create(AMessage);
  FHttpStatusCode := AHttpStatusCode;
  FErrorType := AErrorType;
  FHint := AHint;
  FRedirectUri := ARedirectUri;
  FPayload := TJSONObject.Create;
  FPayload.AddPair('error', AErrorType);
  FPayload.AddPair('error_description', AMessage);
  if not FHint.IsEmpty then
    FPayload.AddPair('hint', FHint);
end;

destructor EOAuth2ServerException.Destroy;
begin
  FPayload.Free;
  inherited;
end;

function EOAuth2ServerException.GenerateHttpResponse(AResponse: TWebResponse; const AUseFragment: Boolean = False): TWebResponse;
var
  LPayload: TJSONObject;
  LAuthScheme: string;
  LRedirectUri: string;
  LQueryPayload: TArray<string>;
  I: Integer;
begin
  Result := AResponse;

  LPayload := GetPayload;

  AResponse.ContentType := 'application/json';

  if (FErrorType = 'invalid_client') and (not FRequest.Authorization.IsEmpty) then
  begin
    LAuthScheme := 'Basic';
    if FRequest.Authorization.StartsWith('bearer', True) then
      LAuthScheme := 'Bearer';
    AResponse.WWWAuthenticate := Format('%s realm="OAuth"', [LAuthScheme]);
  end;

  if not FRedirectUri.IsEmpty then
  begin
    LRedirectUri := FRedirectUri;
    if AUseFragment then
    begin
      if not LRedirectUri.Contains('#') then
        LRedirectUri := LRedirectUri + '#'
      else
        LRedirectUri := LRedirectUri + '&'
    end
    else
    begin
      if not LRedirectUri.Contains('?') then
        LRedirectUri := LRedirectUri + '?'
      else
        LRedirectUri := LRedirectUri + '&'
    end;

    LQueryPayload := [];
    for I := 0 to Pred(LPayload.Count) do
      LQueryPayload := LQueryPayload + [Format('%s=%s', [LPayload.Pairs[I].JsonString.Value, LPayload.Pairs[I].JsonValue.Value])];

    AResponse.StatusCode := 302;
    AResponse.Location := LRedirectUri + string.Join('&', LQueryPayload);

  end
  else
  begin
    AResponse.StatusCode := FHttpStatusCode;
    AResponse.Content := LPayload.ToJSON;
  end;
end;

function EOAuth2ServerException.GetErrorType: string;
begin
  Result := GetErrorType;
end;

function EOAuth2ServerException.GetHint: string;
begin
  Result := FHint;
end;

function EOAuth2ServerException.GetHttpStatusCode: Integer;
begin
  Result := FHttpStatusCode;
end;

function EOAuth2ServerException.GetPayload: TJSONObject;
begin
  Result := FPayload;
end;

function EOAuth2ServerException.GetRedirectUri: string;
begin
  Result := FRedirectUri;
end;

class function EOAuth2ServerException.InvalidClient(ARequest: TWebRequest): EOAuth2ServerException;
begin
  Result := Create('Client authentication failed', 4, 'invalid_client', 401, EmptyStr, EmptyStr);
  Result.SetServerRequest(ARequest);
end;

class function EOAuth2ServerException.InvalidCredentials: EOAuth2ServerException;
begin
  Result := Create('The user credentials were incorrect', 6, 'invalid_credentials', 401, EmptyStr, EmptyStr);
end;

class function EOAuth2ServerException.InvalidGrant(const AHint: string): EOAuth2ServerException;
begin
  Result := Create(
    'The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token ' +
    'is invalid, expired, revoked, does not match the redirection URI used in the authorization request, ' +
    'or was issued to another client',
    10, 'invalid_grant', 400, AHint, EmptyStr);
end;

class function EOAuth2ServerException.InvalidRefreshToken(const AHint: string): EOAuth2ServerException;
begin
  Result := Create('The refresh token is invalid.', 8, 'invalid_request', 401, AHint, EmptyStr);
end;

class function EOAuth2ServerException.InvalidRequest(AParameter: string; const AHint: string = ''): EOAuth2ServerException;
var
  LErrorMessage: string;
  LHint: string;
begin
  LErrorMessage := 'The request is missing a required parameter, includes an invalid parameter value, ' +
    'includes a parameter more than once, or is otherwise malformed';
  if AHint.IsEmpty then
    LHint := Format('Check the ''%s'' parameter', [AParameter])
  else
    LHint := AHint;
  Result := Create(LErrorMessage, 3, 'invalid_request', 400, LHint, EmptyStr);
end;

class function EOAuth2ServerException.InvalidScope(AScope: string; const ARedirectUri: string): EOAuth2ServerException;
var
  LErrorMessage: string;
  LHint: string;
begin
  LErrorMessage := 'The requested scope is invalid, unknown, or malformed';
  if AScope.IsEmpty then
    LHint := 'Specify a scope in the request or set a default scope'
  else
    LHint := Format('Check the ''%s'' scope', [AScope]);
  Result := Create(LErrorMessage, 5, 'invalid_scope', 400, LHint, ARedirectUri);
end;

class function EOAuth2ServerException.ServerError(const AHint: string): EOAuth2ServerException;
begin
  Result := Create(
    Format('The authorization server encountered an unexpected condition which prevented it from fulfilling ' +
    'the request: %s', [AHint]),
    10, 'invalid_grant', 500, EmptyStr, EmptyStr);
end;

procedure EOAuth2ServerException.SetServerRequest(ARequest: TWebRequest);
begin
  FRequest := ARequest;
end;

class function EOAuth2ServerException.UnsupportedGrantType: EOAuth2ServerException;
var
  LErrorMessage: string;
  LHint: string;
begin
  LErrorMessage := 'The authorization grant type is not supported by the authorization server';
  LHint := 'Check that all required parameters have been provided';
  Result := Create(LErrorMessage, 2, 'unsupported_grant_type', 400, LHint, EmptyStr);
end;

end.
