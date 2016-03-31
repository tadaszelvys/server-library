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
    * [ ] [Initiating Login from third party](http://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin)
    * [ ] [Claims](http://openid.net/specs/openid-connect-core-1_0.html#Claims)
        * [x] [Standard Claims](http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) and [Scope Claims](http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
            * [x] Scope `profile`
            * [x] Scope `email`
            * [x] Scope `phone`
            * [x] Scope `address`
            * [x] Custom Scope
        * [ ] [Claims Languages and Scripts](http://openid.net/specs/openid-connect-core-1_0.html#ClaimsLanguagesAndScripts)
        * [x] [UserInfo Endpoint](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
        * [ ] [Requesting Claims using the "claims" Request Parameter](http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
        * [ ] [Aggregated and Distributed Claims](http://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
    * [x] [Passing Request Parameters as JWTs](http://openid.net/specs/openid-connect-core-1_0.html#JWTRequests)
        * [x] Passing a Request Object by Value
        * [x] Passing a Request Object by Reference
        * [x] Encrypted Request Object
    * [ ] [Self-Issued OpenID Provider](http://openid.net/specs/openid-connect-core-1_0.html#SelfIssued)
    * [ ] [Subject Identifier Types](http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
        * [x] `public`
        * [x] `pairwise` (*experimental*)
            * [x] Hashed Subject Identifier
            * [x] Encrypted Subject Identifier
            * [x] Ability to support other Subject Identifier Calculation Algorithms
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
            * [ ] [Rotation of Asymmetric Signing Keys](http://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)
        * [x]  Encryption
           * [ ] [Rotation of Asymmetric Encryption Keys](http://openid.net/specs/openid-connect-core-1_0.html#RotateEncKeys)
    * [ ] [Offline Access](http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess)
    * [ ] [Using Refresh Tokens](http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens)
* [ ] [Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
* [ ] [Dynamic Registration](http://openid.net/specs/openid-connect-registration-1_0.html) and Dynamic Client Registration Protocol ([RFC7591](https://tools.ietf.org/html/rfc7591))
* [ ] Dynamic Client Registration Management Protocol ([RFC7592](https://tools.ietf.org/html/rfc7592))
* [x] [Multiple response types](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
* [x] [Form post response mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
* [ ] [Session Management](http://openid.net/specs/openid-connect-session-1_0.html)
* [ ] [HTTP Based logout](http://openid.net/specs/openid-connect-logout-1_0.html)
* [x] [JWT Authorization Request](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq) (experimental)
    * [x] Request Objects support (this feature is disabled by default)
    * [x] Request Object References support (this feature is disabled by default)
    * [x] Encrypted Request Objects support (this feature is disabled by default)
