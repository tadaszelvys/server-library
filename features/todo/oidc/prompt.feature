Feature: A client can set a "prompt" parameter for each authorization request

  Scenario: A client tries to send a request with prompt none but the resource owner is not logged in
    Given a client sends an  authorization request with the "prompt=none" parameter but the resource owner is not logged in
    Then the status code of the response is "302"
    And the redirection starts with "https://example.com/redirection/callback"
    And the redirect fragment should contain parameter "error" with value "login_required"
    And the redirect fragment should contain parameter "state" with value "state123"
