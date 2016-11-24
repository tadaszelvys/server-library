Feature: A client requests an authorization
  In order to display an authorization page
  translated in the language selected by the user
  a parameter can be set in the query string

  Scenario: A Client requests an access token using the authorization code grant type. The ui_locales is set in the query parameter and a locale is supported.
    Given I am logged in as "john"
    And I add key "client_id" with value "bar" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "code" in the query parameter
    And I add key "state" with value "0123456789" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I add key "ui_locales" with value "fr_FR fr en" in the query parameter
    When I am on the page "https://oauth2.test/application/authorize"
    Then print last response
    And I should see "a besoin de votre autorisation pour accéder à vos resources."

  Scenario: A Client requests an access token using the authorization code grant type. The ui_locales is set in the query parameter but none of them is supported.
    Given I am logged in as "john"
    And I add key "client_id" with value "bar" in the query parameter
    And I add key "scope" with value "scope1 scope2" in the query parameter
    And I add key "response_type" with value "code" in the query parameter
    And I add key "state" with value "0123456789" in the query parameter
    And I add key "redirect_uri" with value "https://example.com/redirection/callback" in the query parameter
    And I add key "ui_locales" with value "de_DE de" in the query parameter
    When I am on the page "https://oauth2.test/application/authorize"
    Then print last response
    And I should see "needs your authorization to get access on your resources."
