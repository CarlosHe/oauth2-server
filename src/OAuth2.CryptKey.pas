unit OAuth2.CryptKey;

interface

uses
  System.RegularExpressions,
  System.SysUtils;

type

  TOAuth2CryptKey = class
  private
  { private declarations }
    const
    RSA_KEY_PATTERN = '^(-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----)*([a-z0-9+/=]+)*(-----END (RSA )?(PUBLIC|PRIVATE) KEY-----)?$';
  private
    { private declarations }
    FKey: string;
    FKeyPath: string;
    FPassPhrase: string;
  protected
    { protected declarations }
    function SaveKeyToFile(AKey: string): string;
  public
    { public declarations }
    constructor Create(AKey: string; const APassPhrase: string = ''; const AKeyPermissionsCheck: Boolean = true);
    function GetKey: string;
    function GetKeyPath: string;
    function GetPassPhrase: string;
    class function New(AKey: string; const APassPhrase: string = ''; const AKeyPermissionsCheck: Boolean = true): TOAuth2CryptKey;
  end;

implementation

uses
  System.Classes,
  System.Hash,
  System.IOUtils;

{ TOAuth2CryptKey }

{$WARN SYMBOL_PLATFORM OFF}


constructor TOAuth2CryptKey.Create(AKey: string; const APassPhrase: string = ''; const AKeyPermissionsCheck: Boolean = true);
var
  LKeyPath: string;
  LRegEx: TRegEx;
  LRSAMath: TMatch;
  LFileAttributes: TFileAttributes;
begin
  LRegEx := TRegEx.Create(RSA_KEY_PATTERN, [TRegExOption.roIgnoreCase]);

  LRSAMath := LRegEx.Match(AKey.Replace(#10,''));

  if LRSAMath.Success then
    LKeyPath := SaveKeyToFile(AKey)
  else
    raise Exception.Create('PCRE error encountered during key match attempt');

  if (not(TFile.Exists(LKeyPath))) then
    raise Exception.Create(Format('Key path ''%s'' does not exists', [LKeyPath]));

  if (AKeyPermissionsCheck) then
  begin
    LFileAttributes := TFile.GetAttributes(LKeyPath);
    if (not({$IFDEF POSIX}TFileAttribute.faOwnerRead{$ENDIF}{$IFDEF MSWINDOWS}TFileAttribute.faNormal{$ENDIF} in LFileAttributes)) then
    begin
      raise Exception.Create(Format(
{$IFDEF POSIX}
        'Key file ''%s'' permissions are not correct, recommend changing to Normal'
{$ENDIF}
{$IFDEF MSWINDOWS}
        'Key file ''%s'' permissions are not correct, recommend changing to 600'
{$ENDIF}
        , [LKeyPath]));
    end;
  end;

  FKey := AKey;
  FKeyPath := LKeyPath;
  FPassPhrase := APassPhrase;
end;
{$WARN SYMBOL_PLATFORM ON}


function TOAuth2CryptKey.GetKey: string;
begin
  Result := FKey;
end;

function TOAuth2CryptKey.GetKeyPath: string;
begin
  Result := FKeyPath;
end;

function TOAuth2CryptKey.GetPassPhrase: string;
begin
  Result := FPassPhrase;
end;

class function TOAuth2CryptKey.New(AKey: string; const APassPhrase: string; const AKeyPermissionsCheck: Boolean): TOAuth2CryptKey;
begin
  Result := TOAuth2CryptKey.Create(AKey, APassPhrase, AKeyPermissionsCheck);
end;

{$WARN SYMBOL_PLATFORM OFF}


function TOAuth2CryptKey.SaveKeyToFile(AKey: string): string;
var
  LTempDir: string;
  LKeyPath: string;
  LFileStream: TFileStream;
  LKeyBytes: TArray<Byte>;
  LFileAttributes: TFileAttributes;
begin
  LTempDir := TPath.GetTempPath;
  LKeyPath := TPath.Combine(LTempDir, THashSHA1.GetHashString(AKey) + '.key');

  if TFile.Exists(LKeyPath) then
    Exit(LKeyPath);

  LFileStream := TFileStream.Create(LKeyPath, fmCreate);
  try
    LKeyBytes := TEncoding.UTF8.GetBytes(AKey);
    LFileStream.Write(LKeyBytes, Length(LKeyBytes));
  finally
    LFileStream.Free;
  end;

  try
    LFileAttributes :=
{$IFDEF POSIX}
      [TFileAttribute.faOwnerRead, TFileAttribute.faOwnerWrite]
{$ENDIF}
{$IFDEF MSWINDOWS}
      [TFileAttribute.faNormal]
{$ENDIF}
      ;
    TFile.SetAttributes(LKeyPath, LFileAttributes);
  except

    raise Exception.Create(Format(
{$IFDEF POSIX}
      'The key file ''%s'' file mode could not be changed with Normal'
{$ENDIF}
{$IFDEF MSWINDOWS}
      'The key file ''%s'' file mode could not be changed with chmod to 600'
{$ENDIF}
      , [LKeyPath]));
  end;

  Exit(LKeyPath);

end;
{$WARN SYMBOL_PLATFORM ON}

end.
