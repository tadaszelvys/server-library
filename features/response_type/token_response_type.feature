Feature: A client requests an authorization code using the Token Response Type

  Scenario: A client sends a authorization requests with the Implicit Response Type. The Resource Owner accepts it.
    Given A client sends a authorization requests with the Implicit Response Type
    When the Resource Owner accepts the authorization request
    Then the client should be redirected
    And the redirection Uri starts with "https://example.com/redirection/callback"
    And the redirection Uri fragment should contain a parameter "access_token"
    And an access token creation event is thrown

  Scenario: A client sends a authorization requests with the Implicit Response Type. The Resource Owner rejects it.
    Given A client sends a authorization requests with the Implicit Response Type
    When the Resource Owner rejects the authorization request
    Then the client should be redirected
    And the redirect fragment should contain parameter "error" with value "access_denied"
    And the redirect fragment should contain parameter "error_description" with value "The resource owner denied access to your client"
    And no access token creation event is thrown

  Scenario: A client sends a authorization requests with the Implicit Response Type with form_post response mode. The Resource Owner accepts it.
    Given A client sends a authorization requests with the Implicit Response Type
    When the Resource Owner accepts the authorization request
    Then the response code is 200
    And the response contains a form
    And the form in the response contains a hidden input with name "access_token"
    And an access token creation event is thrown
    And print last response
