unit OAuth2.Provider.Crypto;

interface

type
  TOAuth2CryptoProvider = class
  public
    { public declarations }
    class function EncryptWithPassword(AUnencryptedData: string; AEncryptionKey: string): string;
    class function DecryptWithPassword(ADecryptedData: string; AEncryptionKey: string): string;
  end;

implementation


uses
  System.Classes,
  OpenSSL.EncUtils;

{ TOAuth2CryptoProvider }

class function TOAuth2CryptoProvider.DecryptWithPassword(ADecryptedData, AEncryptionKey: string): string;
var
  LEncUtil: TEncUtil;
  LInputStream: TStringStream;
  LOutputStream: TStringStream;
begin
  LEncUtil := TEncUtil.Create;
  try
    LEncUtil.UseBase64 := True;
    LEncUtil.Passphrase := AEncryptionKey;
    LEncUtil.Cipher := 'AES-256';
    LInputStream := TStringStream.Create(ADecryptedData);
    LOutputStream := TStringStream.Create;
    try
      LEncUtil.Decrypt(LInputStream, LOutputStream);
      Result := LOutputStream.DataString;
    finally
      LInputStream.Free;
      LOutputStream.Free;
    end;
  finally
    LEncUtil.Free;
  end;
end;

class function TOAuth2CryptoProvider.EncryptWithPassword(AUnencryptedData, AEncryptionKey: string): string;
var
  LEncUtil: TEncUtil;
  LInputStream: TStringStream;
  LOutputStream: TStringStream;
begin
  LEncUtil := TEncUtil.Create;
  try
    LEncUtil.UseBase64 := True;
    LEncUtil.Passphrase := AEncryptionKey;
    LEncUtil.Cipher := 'AES-256';
    LInputStream := TStringStream.Create(AUnencryptedData);
    LOutputStream := TStringStream.Create;
    try
      LEncUtil.Encrypt(LInputStream, LOutputStream);
      Result := LOutputStream.DataString;
    finally
      LInputStream.Free;
      LOutputStream.Free;
    end;
  finally
    LEncUtil.Free;
  end;
end;

end.
