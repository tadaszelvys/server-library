Feature: A client want to know the authorization server configuration

  Scenario: A Client send a request to the metadata endpoint.
    Given A Client send a request to the metadata endpoint
    Then the response code is 200
    And the content type is "application/json"
    And the response is a JSON object
    And print last response
