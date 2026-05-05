# Overview

Trino Proxy supports the use of OIDC Token Exchange + Refresh tokens as the preferred approach to providing a properly scoped Access Token for use within Trino and provide automatic refresh of the Access Token for the lifespan of the Refresh Token.  Examples of downstream services include `Secure Data Catalog`
and `Secure Object Proxy`

Requirements:
* IDP supports [Standard Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
* IDP supports `requested_token_type` = `urn:ietf:params:oauth:token-type:refresh_token` .  


## Example Token Exchange Setup Keycloak + Trino Proxy

Keycloak Token Exchange Notes

Requirements:
* Keycloak deployed with [standard token exchange](https://www.keycloak.org/securing-apps/token-exchange) (not legacy token exchange).  
* the OIDC client identified by `oidcClient.tokenExchangeClientId` has Standard Token Exchange Enabled
* Allow refresh token in Standard Token Exchange set to `Same Session`

### Client Scopes

TODO

