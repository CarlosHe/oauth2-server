unit OAuth2.Grant.AbstractAuthorize;

interface

uses
  System.Net.HttpClient,
  System.Generics.Collections,
  OAuth2.Grant.AbstractGrant;

type

  TAbstractAuthorizeGrant = class(TOAuth2AbstractGrant)
  private
    { private declarations }
  protected
    { protected declarations }
  public
    { public declarations }
    function MakeRedirectUri(AUri: string; AParams: TArray<TPair<string, string>>; const AQueryDelimiter: string = '?'): string;
  end;

implementation

uses
  System.SysUtils,
  System.NetEncoding;

{ TAbstractAuthorizeGrant }

function TAbstractAuthorizeGrant.MakeRedirectUri(AUri: string; AParams: TArray<TPair<string, string>>; const AQueryDelimiter: string): string;
var
  I: Integer;
  LQueryParamCollection: TArray<string>;
begin
  Result := AUri;
  if AUri.Contains(AQueryDelimiter) then
    Result := Result + '&'
  else
    Result := Result + AQueryDelimiter;
  LQueryParamCollection := [];
  for I := Low(AParams) to High(AParams) do
    LQueryParamCollection := LQueryParamCollection + [Format('%s=%s', [AParams[I].Key, AParams[I].Value ])];
  if Length(LQueryParamCollection) > 0 then
    Result := TURLEncoding.URL.EncodeQuery(Result + string.Join('&', LQueryParamCollection));
end;

end.
