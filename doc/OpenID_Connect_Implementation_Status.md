OpenID Connect Implementeation Status
=====================================

* [ ] [Core](http://openid.net/specs/openid-connect-core-1_0.html)
    *  [x] [ID Token](http://openid.net/specs/openid-connect-core-1_0.html#IDToken)
    * [Response types](http://openid.net/specs/openid-connect-core-1_0.html#Authentication):
        * [x] `code`: Authorization Code Flow
        * [x] `id_token`: Implicit Flow
        * [x] `id_token token`: Implicit Flow
        * [x] `code id_token`: Hybrid Flow
        * [x] `code token`: Hybrid Flow
        * [x] `code id_token token`: Hybrid Flow
    * [Initiating Login from third party](http://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin) *RP side only*
    * [ ] [Claims](http://openid.net/specs/openid-connect-core-1_0.html#Claims)
        * [x] [Standard Claims](http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) and [Scope Claims](http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
            * [x] Scope `profile`
            * [x] Scope `email`
            * [x] Scope `phone`
            * [x] Scope `address`
            * [x] Custom Scope
        * [x] [Claims Languages and Scripts](http://openid.net/specs/openid-connect-core-1_0.html#ClaimsLanguagesAndScripts)
        * [x] [UserInfo Endpoint](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
        * [x] [Requesting Claims using the "claims" Request Parameter](http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) *Partial Support*
        * [x] [Aggregated and Distributed Claims](http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
    * [x] [Passing Request Parameters as JWTs](http://openid.net/specs/openid-connect-core-1_0.html#JWTRequests)
        * [x] Passing a Request Object by Value
        * [x] Passing a Request Object by Reference
        * [x] Encrypted Request Object
    * [Self-Issued OpenID Provider](http://openid.net/specs/openid-connect-core-1_0.html#SelfIssued) *Out of the scope of this project*
    * [x] [Subject Identifier Types](http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
        * [x] `public`
        * [x] `pairwise`
            * [x] Hashed Subject Identifier
            * [x] Encrypted Subject Identifier
            * [x] Ability to support other Subject Identifier Calculation Algorithms
        * [x] Ability to 
    * [x]  [Client Authentication](http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
        * [x] Authentication Methods:
            * [x] `client_secret_basic`
            * [x] `client_secret_post` (disabled by default)
            * [x] `client_secret_jwt`
            * [x] `private_key_jwt`
            * [x] `none` (public and unregistered clients supported)
            * [x] Ability to support custom authentication methods
    * [x]  [Signature and encryption](http://openid.net/specs/openid-connect-core-1_0.html#SigEnc)
        * [x]  Signing
        * [x]  Encryption
    * [x] [Offline Access](http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess)
    * [x] [Using Refresh Tokens](http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens)
* [x] [Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
    * [x] [Issuer Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
    * [x] [OpenID Provider Metadata](http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
    * [x] [Obtaining OpenID Provider Configuration Information](http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)
* [ ] [Dynamic Registration](http://openid.net/specs/openid-connect-registration-1_0.html) and Dynamic Client Registration Protocol ([RFC7591](https://tools.ietf.org/html/rfc7591))
* [ ] Dynamic Client Registration Management Protocol ([RFC7592](https://tools.ietf.org/html/rfc7592))
* [x] [Multiple response types](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
* [x] [Form post response mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
* [ ] [Session Management](http://openid.net/specs/openid-connect-session-1_0.html)
* [ ] [Front-Channel logout](http://openid.net/specs/openid-connect-frontchannel-1_0.html)
* [ ] [Back-Channel logout](http://openid.net/specs/openid-connect-backchannel-1_0.html)
* [x] [JWT Authorization Request](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq)
    * [x] Request Objects support (this feature is disabled by default)
    * [x] Request Object References support (this feature is disabled by default)
    * [x] Encrypted Request Objects support (this feature is disabled by default)
