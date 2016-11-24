Feature: A client needs information about a token
  In order get information about a token
  A client should send a request to the server
  and, if authorized, retrieve information

  Scenario: A client can get information of a token
    Given I add key "token" with value "ABCD" in the query parameter
    When I get the request to "https://oauth2.test/token/introspection"
    Then I should receive an authentication error
    And the status code of the response is 401

  Scenario: A client tries to get information of a token of another client
    Given I add key "X-OAuth2-Public-Client-ID" with value "foo" in the header
    And I add key "token" with value "EFGH" in the query parameter
    When I get the request to "https://oauth2.test/token/introspection"
    And the status code of the response is 400
