Feature: A client requests an access token using the JWT Bearer Grant Type

  Scenario: A client sends a JWT Bearer Grant Type request but client is not authenticated
    Given An unauthenticated client sends a JWT Bearer Grant Type request
    Then the response contains an error with code 400
    And the error is "invalid_request"
    And the error description is "Client not authenticated."
    And no access token creation event is thrown

  Scenario: A client sends a JWT Bearer Grant Type request but the assertion is missing
    Given An client sends a JWT Bearer Grant Type request without assertion
    Then the response contains an error with code 400
    And the error is "invalid_request"
    And the error description is "The parameter '' is missing."
    And no access token creation event is thrown

  Scenario: A client sends a valid JWT Bearer Grant Type request
    Given A client sends a valid JWT Bearer Grant Type request
    Then the response code is 200
    And the response contains an access token
    And an access token creation event is thrown

  Scenario: A client sends a valid JWT Bearer Grant Type request but this grant type is not allowed to the client
    Given A client sends a valid JWT Bearer Grant Type request but the grant type is not allowed
    Then the response contains an error with code 400
    And the error is "unauthorized_client"
    And the error description is "The grant type 'urn:ietf:params:oauth:grant-type:jwt-bearer' is unauthorized for this client."
    And no access token creation event is thrown
