Feature: A client can set a "prompt" parameter for each authorization request

  Scenario: A client tries to send a request with prompt none but the resource owner is not logged in
    Given I add key "prompt" with value "none" in the query parameter
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "token" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    When I am on the page "https://oauth2.test/application/authorize"
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect fragment should contain parameter "error" with value "login_required"
    And the redirect fragment should contain parameter "state" with value "state123"
