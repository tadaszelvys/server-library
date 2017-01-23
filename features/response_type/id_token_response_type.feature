Feature: A client requests an Id Token the Id Token Response Type

  Scenario: A client sends a authorization requests with the Authorization Code Response Type and the Resource Owner accepts it.
    Given A client sends a authorization requests with the Authorization Code Response Type
    When the Resource Owner accepts the authorization request
    Then the client should be redirected
    And the redirection Uri starts with "https://example.com/redirection/callback"
    And the redirection Uri query should contain a parameter "code"
    And an authorization code creation event is thrown

  Scenario: A client sends a authorization requests with the Authorization Code Response Type and code verifier and the Resource Owner accepts it.
    Given A client sends a authorization requests with the Authorization Code Response Type and a code verifier
    When the Resource Owner accepts the authorization request
    Then the client should be redirected
    And the redirection Uri starts with "https://example.com/redirection/callback"
    And the redirection Uri query should contain a parameter "code"
    And an authorization code creation event is thrown

  Scenario: A client sends a authorization requests with the Authorization Code Response Type and the Resource Owner rejects it.
    Given A client sends a authorization requests with the Authorization Code Response Type
    When the Resource Owner rejects the authorization request
    Then the client should be redirected
    And the redirection Uri starts with "https://example.com/redirection/callback"
    And the redirection ends with "#_=_"
    And the redirect query should contain parameter "error" with value "access_denied"
    And the redirect query should contain parameter "error_description" with value "The resource owner denied access to your client"
    And an authorization code creation event is thrown

  Scenario: A client has a valid authorization code and use it to get an access token
    Given A client sends a Authorization Code Grant Type request but the redirection Uri parameter is missing
    Then the response contains an error with code 400
    And the error is "invalid_request"
    And the error description is "The redirect Uri is missing or does not match."
    And no access token creation event is thrown

  Scenario: A client has a valid authorization code and use it to get an access token
    Given A client sends a Authorization Code Grant Type request but the redirection Uri parameter mismatch
    Then the response contains an error with code 400
    And the error is "invalid_request"
    And the error description is "The redirect Uri is missing or does not match."
    And no access token creation event is thrown

  Scenario: A client has a valid authorization code and use it to get an access token
    Given A client sends a valid Authorization Code Grant Type request
    Then the response code is 200
    And the response contains an access token
    And an access token creation event is thrown
    And an authorization code used event is thrown

  Scenario: A client has a valid authorization code and use it to get an access token with reduced scope
    Given A client sends a valid Authorization Code Grant Type request with reduced scope
    Then the response code is 200
    And the response contains an access token
    And an access token creation event is thrown
    And an authorization code used event is thrown

  Scenario: A client has a valid authorization code and use it to get an access token but requested scope are not authorized
    Given A client sends a Authorization Code Grant Type request but a scope is not allowed
    Then the response contains an error with code 400
    And the error is "invalid_scope"
    And the error description is "An unsupported scope was requested. Available scopes are: scope1, scope2."
    And no access token creation event is thrown

  Scenario: A client has a valid authorization code and use it to get an access token but associated client_id is not valid
    Given A client sends a Authorization Code Grant Type request but a authorization code is for another client
    Then the response contains an error with code 400
    And the error is "invalid_grant"
    And the error description is "Code doesn't exist or is invalid for the client."
    And no access token creation event is thrown

  Scenario: A client has an expired authorization code
    Given A client sends a Authorization Code Grant Type request but the authorization code expired
    Then the response contains an error with code 400
    And the error is "invalid_grant"
    And the error description is "The authorization code has expired."
    And no access token creation event is thrown

  Scenario: A client has an authorization code with a code_verifier parameter but that parameter is missing
    Given A client sends a Authorization Code Grant Type request but the authorization code requires a code_verifier parameter
    Then the response contains an error with code 400
    And the error is "invalid_grant"
    And the error description is "The parameter 'code_verifier' is missing or invalid."
    And no access token creation event is thrown

  Scenario: A client has an authorization code with a code_verifier parameter but that parameter is invalid
    Given A client sends a Authorization Code Grant Type request but the code_verifier parameter of the authorization code is invalid
    Then the response contains an error with code 400
    And the error is "invalid_grant"
    And the error description is "The parameter 'code_verifier' is missing or invalid."
    And no access token creation event is thrown

  Scenario: A client has an authorization code with a code_verifier parameter (plain)
    Given A client sends a valid Authorization Code Grant Type request with code verifier (plain)
    Then the response code is 200
    And the response contains an access token
    And an access token creation event is thrown
    And an authorization code used event is thrown

  Scenario: A client has an authorization code with a code_verifier parameter (S256)
    Given A client sends a valid Authorization Code Grant Type request with code verifier (S256)
    Then the response code is 200
    And the response contains an access token
    And an access token creation event is thrown
    And an authorization code used event is thrown
