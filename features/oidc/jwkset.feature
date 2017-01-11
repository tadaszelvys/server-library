Feature: Public keys are available through an endpoint

  Scenario: The public keys are available through an Url
    When I am on the page "https://oauth2.test/keys/public.jwkset.json"
    Then the status code of the response is 200
    And the content type is "application/jwk-set+json"
