Feature: Remote sign-in from another device
  An agent on a cloud machine has no browser. It starts a sign-in, prints an approval URL and a short matching
  code, and waits. The person opens the URL on another device, checks the code, signs in and approves. Only that
  waiting CLI receives a session, and nothing secret passes through chat: the broker sees only hashes of the
  CLI's two secrets, and the code it holds for a moment is useless without the CLI's PKCE verifier.

  Background:
    Given a product with a broker and its approval pages

  Scenario: An approved sign-in gives the waiting CLI its session
    When the CLI starts a remote sign-in
    And the person approves it in their browser after checking the code
    Then the CLI stores one session
    And the CLI printed only the approval URL and the matching code

  Scenario: A denied sign-in gives nothing
    When the CLI starts a remote sign-in
    And the person denies it on the approval page
    Then the CLI reports that the sign-in was denied
    And no session is stored

  Scenario: A sign-in nobody approves expires
    When the CLI starts a remote sign-in
    And nobody approves it for ten minutes
    Then the CLI reports that the approval link expired
    And no session is stored

  Scenario: A used approval link cannot be used again
    Given a remote sign-in that was approved and collected
    When someone opens the same approval link
    Then the page says the link is no longer valid

  Scenario: Someone who knows the link cannot attach their own sign-in to it
    When the CLI starts a remote sign-in
    And someone else binds the link before the person approves
    And the person tries to approve it
    Then the page says the link is no longer valid

  Scenario: A callback from another browser is refused
    When the CLI starts a remote sign-in
    And the person approves it and the sign-in returns to a different browser
    Then the callback page refuses it
    And the broker holds no code for the sign-in

  Scenario: Only a poll that knows the poll secret receives the code, and only once
    Given a remote sign-in the person has approved
    When a poll without the poll secret asks for it
    Then that poll is told the sign-in does not exist
    And the CLI's own poll receives the code exactly once

  Scenario: A sign-in for a target the broker does not serve is refused
    When a CLI starts a remote sign-in for another target
    Then the broker refuses to start it

  Scenario: Tokens issued for another request are not stored
    When the CLI starts a remote sign-in
    And the person approves it but the sign-in provider answers tokens for a different nonce
    Then the CLI reports that the tokens were for a different request
    And no session is stored

  Scenario: Someone who reads the link in chat and approves first does not get the session
    Given the CLI expects to be signed in as person@example.test
    When the CLI starts a remote sign-in
    And intruder@example.test approves it first
    Then the CLI reports that someone else approved the sign-in
    And no session is stored

  Scenario: The CLI says who it is signed in as
    Given the CLI expects to be signed in as person@example.test
    When the CLI starts a remote sign-in
    And person@example.test approves it
    Then the CLI stores one session
    And the CLI printed that it is signed in as person@example.test

  Scenario: A caller that starts too many sign-ins is slowed down
    When one caller starts more sign-ins than the broker allows in a minute
    Then the broker refuses the extra one and says when to retry
