Feature: A client uses the Authorization Code Grant Type

  Scenario: A valid authorization request is received and the resource owner accepts the client request
    Given a valid authorization code request is received and the resource owner accepts it
    And the client should be redirected
    And the redirect Uri contains an authorization code

  Scenario: A public client sends a request without code verification parameter
    Given a public client sends a request without code verification parameter
    And the client should be redirected
    And the redirect Uri contains an error
    And the error is "foo"
    And the error description is "foo"

  Scenario: A public client sends a request with an invalid code verification parameter
    Given a public client sends a request with an invalid code verification parameter
    And the client should be redirected
    And the redirect Uri contains an error
    And the error is "foo"
    And the error description is "foo"

  Scenario: A valid token request is received and an access token is issued
    Given a valid authorization code grant is received
    And an access token is issued
