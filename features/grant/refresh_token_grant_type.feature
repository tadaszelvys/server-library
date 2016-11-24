Feature: A client request an access token using the Refresh Token Grant Type
  In order renew an access token
  A client must have a Refresh Token
  And use it once

  Scenario: The request is invalid (refresh token expired)
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "refresh_token" in the body request
    And I add key "refresh_token" with value "INVALID_REFRESH_TOKEN_FOO" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 exception with message 'invalid_grant' and description 'Refresh token has expired'
    And the status code of the response is 400

  Scenario: The request is valid and an access token is issued
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "refresh_token" in the body request
    And I add key "refresh_token" with value "VALID_REFRESH_TOKEN_FOO" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 response
    And the response is not an OAuth2 Exception
    And the response contains an access token
    And the status code of the response is 200

  Scenario: The confidential client is not fully authenticated
    Given I add user 'bar' and password 'bad_secret' in the authorization header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "refresh_token" in the body request
    And I add key "refresh_token" with value "VALID_REFRESH_TOKEN_BAR" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an authentication error
    And the status code of the response is 401

  Scenario: The confidential client is not fully authenticated
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "refresh_token" in the body request
    And I add key "client_id" with value "bar" in the body request
    And I add key "client_secret" with value "bad_secret" in the body request
    And I add key "refresh_token" with value "VALID_REFRESH_TOKEN_BAR" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an authentication error
    And the status code of the response is 401

  Scenario: The request is valid and an access token is issued
    Given I add user 'bar' and password 'secret' in the authorization header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "refresh_token" in the body request
    And I add key "refresh_token" with value "VALID_REFRESH_TOKEN_BAR" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 response
    And the response is not an OAuth2 Exception
    And the response contains an access token
    And the status code of the response is 200

  Scenario: The request is valid and an access token is issued
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "client_id" with value "bar2" in the body request
    And I add key "client_secret" with value "secret" in the body request
    And I add key "grant_type" with value "refresh_token" in the body request
    And I add key "refresh_token" with value "VALID_REFRESH_TOKEN_BAR2" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 response
    And the response is not an OAuth2 Exception
    And the response contains an access token
    And the status code of the response is 200

  Scenario: The request is valid but the client is not authorized
    Given I add user 'baz' and password 'secret' in the authorization header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "refresh_token" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 exception with message 'unauthorized_client' and description 'The grant type "refresh_token" is unauthorized for this client.'
    And the status code of the response is 400
