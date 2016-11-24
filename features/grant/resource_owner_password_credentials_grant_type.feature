Feature: A client request an access token using the ResourceOwner Password Credentials Grant Type
  In order get a protected resource
  A client must get an Access Token
  Using a valid request to the Token Endpoint

  Scenario: The request is invalid
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "password" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 exception with message 'invalid_grant' and description 'Invalid username and password combination'
    And the status code of the response is 400

  Scenario: The request is valid and an access token is issued
    Given I add user 'bar' and password 'secret' in the authorization header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "password" in the body request
    And I add key "username" with value "user1" in the body request
    And I add key "password" with value "password1" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 response
    And the response is not an OAuth2 Exception
    And the response contains an access token
    And the status code of the response is 200

  Scenario: The request is valid but the client is not authorized
    Given I add user 'baz' and password 'secret' in the authorization header
    And I add key "scope" with value "scope1 scope2" in the body request
    And I add key "grant_type" with value "password" in the body request
    When I post the request to "https://oauth2.test/token/get"
    Then I should receive an OAuth2 exception with message 'unauthorized_client' and description 'The grant type "password" is unauthorized for this client.'
    And the status code of the response is 400