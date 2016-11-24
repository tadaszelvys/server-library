Feature: A client want to know the server configuration

  Scenario: A Client send a request to the metadata endpoint.
    Given I am on the page "https://oauth2.test/.well-known/openid-configuration"
    Then the status code of the response is "200"
    And the content type is "application/json"
    And the response is a JSON object
    And print last response
