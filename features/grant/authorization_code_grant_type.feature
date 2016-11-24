Feature: A client requests an authorization
  In order get a protected resource
  A client must get an authorization from resource owner
  Then, it can send a request to the Token Endpoint

  Scenario: A public client cannot use the authorization code grant type
    Given I am logged in as "john"
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "code" in the query parameter
    And I add key "state" with value "0123456789" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    When I am on the page "https://oauth2.test/application/authorize"
    Then I should be redirected
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect query should contain parameter "error" with value "invalid_client"
    And the redirect query should contain parameter "error_description" with value "Public clients are not allowed to use the authorization code grant type."

  Scenario: A Client requests an access token using the authorization code grant type. The Resource Owner accepts the request.
    Given I am logged in as "john"
    And I add key "client_id" with value "bar" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "code" in the query parameter
    And I add key "state" with value "0123456789" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I am on the page "https://oauth2.test/application/authorize"
    When I check "Allow next authorization requests for this client with the same parameters"
    And I uncheck "This is scope 1"
    And I click on "Accept"
    Then I should be redirected
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect query should contain parameter "code"
    And the redirect query should contain Base64Url encoded parameter "code" with length between "50" and "100"
    And the authcode listener should have receive a "oauth2.pre_authcode_creation" event
    And the authcode listener should have receive a "oauth2.post_authcode_creation" event

  Scenario: A Client requests an access token using the authorization code grant type. The Resource Owner rejects the request.
    Given I am logged in as "john"
    And I add key "client_id" with value "bar" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "code" in the query parameter
    And I add key "state" with value "0123456789" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I am on the page "https://oauth2.test/application/authorize"
    When I click on "Reject"
    Then I should be redirected
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirection ends with "#"
    And the redirect query should contain parameter "error" with value "access_denied"
    And the redirect query should contain parameter "error_description" with value "The resource owner denied access to your client"

  Scenario: A client has a valid authorization code and use it to get an access token
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE1" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an access token
    And the access token should contain parameter "token_type" with value "Bearer"
    And the access token should contain parameter "scope" with value "scope1 scope2"
    And the authorization code "VALID_CODE1" does not exist

  Scenario: A client has a valid authorization code and use it to get an access token but the redirect URI parameter mismatch
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE5" in the body request
    And I add key "redirect_uri" with value "https://bad.redirect/uri" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an error "invalid_request"
    And the error has "error_description" with value "The redirect URI is missing or does not match."

  Scenario: A client has a valid authorization code and use it to get an access token but the redirect URI parameter is missing
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE5" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an error "invalid_request"
    And the error has "error_description" with value "The redirect URI is missing or does not match."

  Scenario: A client has a valid authorization code and use it to get an access token with reduced scope
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE2" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an access token
    And the access token should contain parameter "token_type" with value "Bearer"
    And the access token should contain parameter "scope" with value "scope1"

  Scenario: A client has a valid authorization code and use it to get an access token but requested scope are not authorized
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope3" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE3" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an error "invalid_scope"
    And the error has "error_description" with value "An unsupported scope was requested. Available scopes are [scope1,scope2]"

  Scenario: A client has a valid authorization code and use it to get an access token but associated client_id is not valid
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE4" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an error "invalid_grant"
    And the error has "error_description" with value "Code doesn't exist or is invalid for the client."

  Scenario: A client has an expired valid authorization code and use it to get an access token
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "EXPIRED_CODE1" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an error "invalid_grant"
    And the error has "error_description" with value "The authorization code has expired."

  Scenario: A client has a valid authorization code and use it to get an access token but code_verifier parameter is missing
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE_WITH_PKCE_S256" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an error "invalid_request"
    And the error has "error_description" with value 'The parameter "code_verifier" is required.'

  Scenario: A client has a valid authorization code and use it to get an access token but code_verifier parameter is invalid
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE_WITH_PKCE_S256" in the body request
    And I add key "code_verifier" with value "BAD VALUUE" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an error "invalid_request"
    And the error has "error_description" with value 'Invalid parameter "code_verifier".'

  Scenario: A client has a valid authorization code and use it to get an access token using a valid code_verifier (method is "S256")
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE_WITH_PKCE_S256" in the body request
    And I add key "code_verifier" with value "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an access token
    And the access token should contain parameter "token_type" with value "Bearer"
    And the access token should contain parameter "scope" with value "scope1"

  Scenario: A client has a valid authorization code and use it to get an access token using a valid code_verifier (method is "plain")
    Given the request is secured
    And I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "client_id" with value "foo" in the body request
    And I add key "scope" with value "scope1" in the body request
    And I add key "grant_type" with value "authorization_code" in the body request
    And I add key "code" with value "VALID_CODE_WITH_PKCE_PLAIN" in the body request
    And I add key "code_verifier" with value "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" in the body request
    When I "POST" the request to "/token/get"
    Then I should receive an access token
    And the access token should contain parameter "token_type" with value "Bearer"
    And the access token should contain parameter "scope" with value "scope1"
