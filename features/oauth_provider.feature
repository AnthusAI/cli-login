Feature: Talking to the sign-in provider
  Tokens go only to the configured provider, and failures are told apart honestly.

  Scenario: Redirects are refused
    Given a provider endpoint that redirects
    When the tool posts a refresh request
    Then the request is rejected and the redirect is not followed

  Scenario: A rejected grant is an expired session
    Given a provider that answers invalid_grant
    When the tool posts a refresh request
    Then the failure is a permanent session error

  Scenario: A throttled or failing provider is transient
    Given a provider that answers with status 503
    When the tool posts a refresh request
    Then the failure is transient

  Scenario: An insecure endpoint is refused before any request
    When the tool posts to a plain HTTP endpoint
    Then the request is rejected
