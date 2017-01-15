Feature: A client want to know the authorization server configuration

  Scenario: A Client send a request to the metadata endpoint.
    Given a client send a request to the metadata endpoint
    Then the response code is 200
    And the content type of the response is "application/json"
    And the response is a JSON object
    And I print last response
