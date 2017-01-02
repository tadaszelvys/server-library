Feature: A client request an access token
  In order get a protected resource
  A client must get an access token from the authorization server

  Scenario: The client is not authenticated
    Given a client sends a POST revocation request but it is not authenticated
    Then the response contains an error with code 401
    And the error is "invalid_client"
    And the error description is "Client authentication failed."
    And no token revocation event is thrown

  Scenario: The token parameter is missing
    Given a client sends a POST revocation request without token parameter
    Then the response contains an error with code 400
    And the error is "invalid_request"
    And the error description is "The parameter 'token' is missing."
    And no token revocation event is thrown

  Scenario: The token parameter is missing and a callback is set
    Given a client sends a POST revocation request without token parameter with a callback parameter
    Then the response code is 400
    And the response contains
    """
    foo({"error":"invalid_request","error_description":"The parameter 'token' is missing."})
    """
    And no token revocation event is thrown

  Scenario: The request is valid and the access token is revoked
    Given a client sends a valid POST revocation request
    Then the response code is 200
    And a token revocation event is thrown

  Scenario: The request is valid, but no access token is revoked (wrong client)
    Given a client sends a valid POST revocation request but the token owns to another client
    Then the response contains an error with code 400
    And the error is "invalid_request"
    And the error description is "The parameter 'token' is invalid."
    And no token revocation event is thrown
