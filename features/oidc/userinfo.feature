Feature: The authorization server has an Userinfo Endpoint

  Scenario: No access token in the request
    When a client send a Userinfo request without access token
    Then the response contains an error with code 401
    And the error is "invalid_token"
    And the error description is "Access token required."

  Scenario: I have a valid access token in the request header
    When a client sends a valid Userinfo request
    Then the response code is 200
    And the content type of the response is "application/json; charset=UTF-8"
    And the response contains
    """
    {"name":"John Doe","given_name":"John","middle_name":"Jack","family_name":"Doe","nickname":"Little John","preferred_username":"j-d","profile":"https:\/\/profile.doe.fr\/john\/","picture":"https:\/\/www.google.com","website":"https:\/\/john.doe.com","gender":"M","birthdate":"1950-01-01","zoneinfo":"Europe\/Paris","locale":"en","updated_at":1485431232,"email":"root@localhost.com","email_verified":false,"phone_number":"+0123456789","phone_number_verified":true,"sub":"john.1"}
    """

  Scenario: A client sends an access token without openid scope in the request header
    When a client sends a Userinfo request but the access token has no openid scope
    Then the response contains an error with code 403
    And the error is "invalid_token"
    And the error description is "Insufficient scope."

  Scenario: A client sends an access token issued through the token endpoint
    When a client sends a Userinfo request but the access token has not been issued through the authorization endpoint
    Then the response contains an error with code 400
    And the error is "invalid_token"
    And the error description is "The access token has not been issued through the authorization endpoint and cannot be used."
