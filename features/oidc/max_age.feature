Feature: A client requests an authorization
  In order to be sure the user is not connected for a long time
  A client can set the "max_age" query parameter to force user to login again if necessary

  Scenario: A client tries to send a request with max_age but the user must authenticate again
    Given I am logged in as "john"
    When I add key "max_age" with value "10" in the query parameter
    When I add key "ui_locales" with value "fr_FR fr en" in the query parameter
    When I add key "display" with value "wap" in the query parameter
    When I add key "login_hint" with value "john" in the query parameter
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "token" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I am on the page "https://oauth2.test/application/authorize"
    Then the status code of the response is "302"
    And the redirection starts with "https://oauth2.test/login"
    And I follow the redirect
    And I print the session key "oauth2_authorization_request_data"
    And print last response

  Scenario: A client tries to send a request with max_age but the user does not need to authenticate again
    Given I am logged in as "john"
    When I add key "max_age" with value "10000" in the query parameter
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "token" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I am on the page "https://oauth2.test/application/authorize"
    Then the status code of the response is "200"
    And print last response
