unit OAuth2.BearerTokenValidator;

interface

uses
  OAuth2.AuthorizationValidator.Contract,
  OAuth2.Repository.AccessToken.Contract,
  OAuth2.CryptKey,
  Web.HTTPApp;

type

  TOAuth2BearerTokenValidator = class(TInterfacedObject, IOAuth2AuthorizationValidator)
  private
    { private declarations }
    FAccessTokenRepository: IOAuth2AccessTokenRepository;
    FPublicKey: TOAuth2CryptKey;
  protected
    { protected declarations }
  public
    { public declarations }
    constructor Create(AAccessTokenRepository: IOAuth2AccessTokenRepository);
    procedure ValidateBearerToken(AToken: string);
    function ValidateAuthorization(ARequest: TWebRequest): TWebRequest;
    procedure SetPublicKey(AKey: TOAuth2CryptKey);
  end;

implementation

uses
  JOSE.Core.JWT,
  JOSE.Core.Base,
  JOSE.Core.Builder,
  JOSE.Consumer,
  JOSE.Core.JWK,
  JOSE.Context,
  JOSE.Core.JWS,
  OAuth2.Exception.ServerException,
  System.SysUtils,
  System.RegularExpressions,
  System.Classes,
  System.JSON;

{ TOAuth2BearerTokenValidator }

constructor TOAuth2BearerTokenValidator.Create(AAccessTokenRepository: IOAuth2AccessTokenRepository);
begin
  FAccessTokenRepository := AAccessTokenRepository;
end;

procedure TOAuth2BearerTokenValidator.SetPublicKey(AKey: TOAuth2CryptKey);
begin
  FPublicKey := AKey;
end;

function TOAuth2BearerTokenValidator.ValidateAuthorization(ARequest: TWebRequest): TWebRequest;
var
  LHeader: string;
  LToken: string;
begin
  Result := ARequest;

  LHeader := ARequest.Authorization;

  if LHeader.IsEmpty then
    raise EOAuth2ServerException.AccessDenied('Missing ''Authorization'' header');

  if not LHeader.StartsWith('bearer ', True) then
    raise EOAuth2ServerException.AccessDenied('Invalid authorization type');

  LToken := TRegEx.Replace(LHeader, '^(?:\s+)?bearer\s', '', [TRegExOption.roIgnoreCase]);

  ValidateBearerToken(LToken);
end;

procedure TOAuth2BearerTokenValidator.ValidateBearerToken(AToken: string);
var
  LSigner: TJWS;
  LToken: TJWT;
  LJWK: TJWK;
  LValidations: IJOSEConsumer;
  LJWTContext: TJOSEContext;
  LValidationErro: string;
begin
  try
    LJWTContext := TJOSEContext.Create(AToken, TJWTClaims);
    try
      LValidations := TJOSEConsumerBuilder.NewConsumer
        .SetRequireJwtId
        .SetSkipVerificationKeyValidation
        .SetSkipSignatureVerification
        .SetSkipDefaultAudienceValidation
        .SetRequireExpirationTime
        .SetRequireIssuedAt
        .Build;
      try
        LValidations.ProcessContext(LJWTContext);
      except
        LValidationErro := 'the token has expired or the token id was not found';
      end;
    finally
      LJWTContext.Free;
    end;
  except
    LValidationErro := 'the token is in an invalid format';
  end;

  if not LValidationErro.IsEmpty then
    raise EOAuth2ServerException.AccessDenied(Format('The access token could not be verified because %s', [LValidationErro]));

  LToken := TJWT.Create;
  try
    LJWK := TJWK.Create(FPublicKey.GetKey);
    try
      LSigner := TJWS.Create(LToken);
      try
        LSigner.SkipKeyValidation := True;
        LSigner.SetKey(LJWK);
        LSigner.CompactToken := AToken;
        LSigner.SetHeaderAlgorithm('RS256');
        try
          LSigner.VerifySignature;
        except

        end;
      finally
        LSigner.Free;
      end;
    finally
      LJWK.Free;
    end;

    if not LToken.Verified then
      raise EOAuth2ServerException.AccessDenied('Access token could not be verified');

    if FAccessTokenRepository.IsAccessTokenRevoked(LToken.Claims.JWTId) then
      raise EOAuth2ServerException.AccessDenied('Access token has been revoked');

  finally
    LToken.Free;
  end;
end;

end.
