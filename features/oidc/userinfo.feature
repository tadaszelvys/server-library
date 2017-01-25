Feature: The authorization server has an Userinfo Endpoint

  Scenario: No access token in the request
    When a client send a Userinfo request without access token
    Then the response contains an error with code 401
    And the error is "invalid_token"
    And the error description is "Access token required."

  Scenario: I have a valid access token in the request header
    When a client sends a valid Userinfo request
    Then the response code is 200
    And the content type of the response is "application/json"
    And the response contains
    """

    """

  Scenario: I have an access token without openid scope in the request header
    When a client sends a Userinfo request but the access token has no openid scope
    Then the response contains an error with code 400
    And the error is "invalid_request"
    And the error description is "The access token does not contain the 'openid' scope."
