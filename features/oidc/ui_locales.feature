Feature: A client requests an authorization
  In order to display an authorization page
  translated in the language selected by the user
  a parameter can be set in the query string

  Scenario: A client send an authorization request with a ui_locales parameter.
    Given A client sends an authorization request with ui_locales parameter and at least one locale is supported
    Then print last response
    And I should see "a besoin de votre autorisation pour accéder à vos resources."

  Scenario: A client send an authorization request with a ui_locales parameter but none of them is supported.
    Given A client sends an authorization request with ui_locales parameter and none of them is supported
    Then print last response
    And I should see "needs your authorization to get access on your resources."
