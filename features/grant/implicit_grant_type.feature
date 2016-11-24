Feature: A client requests an authorization
  In order get a protected resource
  A client must get an authorization from resource owner

  Scenario: A public client cannot use the authorization code grant type
    Given I am logged in as "john"
    And I add key "client_id" with value "bar" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "token" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    When I am on the page "https://oauth2.test/application/authorize"
    Then I should be redirected
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect fragment should contain parameter "error" with value "invalid_client"
    And the redirect fragment should contain parameter "error_description" with value "Confidential clients are not allowed to use the implicit grant type."

  Scenario: A resource owner accepted the client
    Given I am logged in as "john"
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "token" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I am on the page "https://oauth2.test/application/authorize"
    When I click on "Accept"
    Then I should be redirected
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect fragment should contain parameter "access_token"
    And the redirect fragment should contain parameter "state" with value "state123"

  Scenario: A resource owner accepted the client (with form_post response mode)
    Given I am logged in as "john"
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "openid profile email phone address" in the query parameter
    And I add key "response_type" with value "id_token token" in the query parameter
    And I add key "response_mode" with value "form_post" in the query parameter
    And I add key "nonce" with value "0123456789" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I am on the page "https://oauth2.test/application/authorize"
    When I click on "Accept"
    Then print last response

  Scenario: A resource owner rejected the client
    Given I am logged in as "john"
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "token" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I am on the page "https://oauth2.test/application/authorize"
    When I click on "Reject"
    Then I should be redirected
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect fragment should contain parameter "error" with value "access_denied"
    And the redirect fragment should contain parameter "state" with value "state123"
    And the redirect fragment should contain parameter "error_description" with value "The resource owner denied access to your client"

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

  Scenario: A client tries to send a request with prompt none but the consent screen must be display
    Given I am logged in as "john"
    Given I add key "prompt" with value "none" in the query parameter
    And I add key "client_id" with value "foo" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "token" in the query parameter
    And I add key "state" with value "state123" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    When I am on the page "https://oauth2.test/application/authorize"
    And the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect fragment should contain parameter "error" with value "interaction_required"
    And the redirect fragment should contain parameter "state" with value "state123"

