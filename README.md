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
* [Delphi OpenSSL Library](https://github.com/CarlosHe/Delphi-OpenSSL)
