unit OAuth2.ResponseType.RedirectResponse;

interface

uses
  Web.HTTPApp,
  OAuth2.ResponseType.Abstract;

type

  TOAuth2RedirectResponse = class(TOAuth2AbstractResponseType)
  private
    { private declarations }
    FRedirectUri: string;
  protected
    { protected declarations }
  public
    { public declarations }
    procedure SetRedirectUri(ARedirectUri: string);
    function GenerateHttpResponse(AResponse: TWebResponse): TWebResponse; override;
  end;

implementation

{ TOAuth2RedirectResponse }

function TOAuth2RedirectResponse.GenerateHttpResponse(AResponse: TWebResponse): TWebResponse;
begin
  inherited;
  Result := AResponse;
  AResponse.CustomHeaders.AddPair('pragma', 'no-cache');
  AResponse.CustomHeaders.AddPair('cache-control', 'no-store');
  AResponse.StatusCode := 301;
  AResponse.Location := FRedirectUri;
end;

procedure TOAuth2RedirectResponse.SetRedirectUri(ARedirectUri: string);
begin
  FRedirectUri := ARedirectUri;
end;

end.
