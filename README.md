# Delphi OAuth 2.0 Server for WebBroker

`CarlosHe/oauth2-server` is a standards compliant implementation of an [OAuth 2.0](https://tools.ietf.org/html/rfc6749) authorization server written in Delphi for WebBroker.

Supports the following grants:

* Password credentials grant
* Authorization code grant
* Client credentials grant
* Refresh grant
* Implicit grant

Implemented RFCs:

* [RFC6749 "OAuth 2.0"](https://tools.ietf.org/html/rfc6749)
* [RFC6750 " The OAuth 2.0 Authorization Framework: Bearer Token Usage"](https://tools.ietf.org/html/rfc6750)
* [RFC7519 "JSON Web Token (JWT)"](https://tools.ietf.org/html/rfc7519)
* [RFC7636 "Proof Key for Code Exchange by OAuth Public Clients"](https://tools.ietf.org/html/rfc7636)

## Installation (with boss)

```
boss install github.com/CarlosHe/oauth2-server
```

## Required dependencies for manual installation

* [Delphi JOSE and JWT Library](https://github.com/paolo-rossi/delphi-jose-jwt)
* [BCrypt Library](https://github.com/viniciussanchez/bcrypt)

## Crypto Implementation

This project uses dynamic loading of the system's OpenSSL library for AES-256-CBC encryption. The crypto provider (`OAuth2.Provider.Crypto`) implements:

- **Dynamic OpenSSL loading** - Automatically loads available OpenSSL versions
- **Full compatibility** - Works with OpenSSL 1.0.2, 1.1.x, and 3.x
- **No static dependencies** - No need to link against specific OpenSSL versions
- **Cross-platform support** - Works on Linux (libcrypto.so) and Windows (libeay32.dll)
- **Same API interface** - Maintains compatibility with existing code

### Supported OpenSSL Libraries

The system will automatically try to load these libraries in order:
1. `libcrypto.so.3` (OpenSSL 3.x)
2. `libcrypto.so.1.1` (OpenSSL 1.1.x)
3. `libcrypto.so.1.0.2` (OpenSSL 1.0.2)
4. `libcrypto.so` (Generic Linux)
5. `libeay32.dll` (Windows)
6. `libcrypto-1_1.dll` (Windows)

### Key Derivation

**Important:** This implementation maintains **100% compatibility** with the original OpenSSL implementation:
- Uses the password directly as the encryption key (no derivation)
- Uses the first 16 bytes of the key as the IV
- Same padding and encoding as the original

## Migration from Static OpenSSL

If you're upgrading from a previous version that used static OpenSSL linking:

1. Remove the OpenSSL dependency from your project
2. The new implementation maintains the same API interface
3. **Existing encrypted data is fully compatible** - no re-encryption needed
4. The new implementation works with any available OpenSSL version on the system
