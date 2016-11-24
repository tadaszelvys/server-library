Feature: A client request an access token
  In order get a protected resource
  A client must get an access token from the authorization server

  Scenario: The request has no token parameter
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And the content type is "application/x-www-form-urlencoded;charset=UTF-8;"
    And I add key "callback" with value "foo" in the body request
    When I post the request to "https://oauth2.test/token/revocation"
    Then the response content is 'foo({"error":"invalid_request","error_description":"Parameter \"token\" is missing"})'
    And the status code of the response is 400

  Scenario: The request has no token parameter
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "callback" with value "foo" in the query parameter
    When I post the request to "https://oauth2.test/token/revocation"
    Then the response content is 'foo({"error":"invalid_request","error_description":"Parameter \"token\" is missing"})'
    And the status code of the response is 400

  Scenario: The request is valid and the access token is revoked (public client)
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And the content type is "application/x-www-form-urlencoded;charset=UTF-8;"
    And I add key "callback" with value "bar" in the body request
    And I add key "token" with value "ABCD" in the body request
    And the access token "ABCD" exists
    When I post the request to "https://oauth2.test/token/revocation"
    Then the status code of the response is 200
    And the access token "ABCD" does not exist

  Scenario: The request is valid, but no access token is revoked (wrong client)
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And the content type is "application/x-www-form-urlencoded;charset=UTF-8;"
    And I add key "callback" with value "bar" in the body request
    And I add key "token" with value "EFGH" in the body request
    And the access token "EFGH" exists
    When I post the request to "https://oauth2.test/token/revocation"
    Then the status code of the response is 200
    And the access token "EFGH" exists

  Scenario: The request is valid and the access token is revoked (confidential client)
    Given I add user "bar" and password "secret" in the authorization header
    And the content type is "application/x-www-form-urlencoded;charset=UTF-8;"
    And I add key "callback" with value "bar" in the body request
    And I add key "token" with value "EFGH" in the body request
    And the access token "EFGH" exists
    When I post the request to "https://oauth2.test/token/revocation"
    Then the status code of the response is 200
    And the access token "EFGH" does not exist

  Scenario: The request is valid, but the access token is not revoked (confidential client not authenticated)
    Given I add user "bar" and password "wrong secret" in the authorization header
    And the content type is "application/x-www-form-urlencoded;charset=UTF-8;"
    And I add key "callback" with value "bar" in the body request
    And I add key "token" with value "EFGH" in the body request
    And the access token "EFGH" exists
    When I post the request to "https://oauth2.test/token/revocation"
    Then the status code of the response is 401
    And the access token "EFGH" exists
