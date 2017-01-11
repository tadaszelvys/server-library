Feature: The authorization server has an Userinfo Endpoint

  Scenario: No access token in the request
    When I am on the page "https://oauth2.test/user/info"
    Then I should receive an authentication error
    And the status code of the response is 401

  Scenario: I have a valid access token in the request header
    When I add key "Authorization" with value "Bearer VALID_ACCESS_TOKEN_WITH_OPENID_SCOPE" in the header
    And I am on the page "https://oauth2.test/user/info"
    Then the status code of the response is 200
    And the content type is "application/json"

  Scenario: I have an access token without openid scope in the request header
    When I add key "Authorization" with value "Bearer ABCD" in the header
    And I am on the page "https://oauth2.test/user/info"
    Then the status code of the response is 400
    And the content type is "application/json"
    And I should receive an OAuth2 exception with message "invalid_request" and description 'The access token does not contain the "openid" scope.'
