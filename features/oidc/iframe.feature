Feature: The resource server provides an iframe for session management

  Scenario: The server has an OP iframe endpoint
    When I am on the page "https://oauth2.test/session/manager/iframe"
    Then the status code of the response is 200
    And the content type is "text/html; charset=UTF-8"
