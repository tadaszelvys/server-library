Feature: A client requests an authorization code using the Code Response Type

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
