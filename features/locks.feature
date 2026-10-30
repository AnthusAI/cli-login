Feature: Per-key locks on every operating system
  Several processes can share one signed-in session. Each stored key has its own lock, so processes that use the
  same key take turns and never lose a rotated refresh token, while processes that use different keys never wait
  for each other. The same behaviour holds on macOS, Linux and Windows.

  Scenario: Processes using the same key take turns
    Given a private state directory
    When 4 real processes each add 1 to a shared counter 5 times while holding the lock for key "key-1"
    Then the counter reads 20

  Scenario: A different key is never blocked
    Given a private state directory
    And a real process holds the lock for key "key-1"
    When this process takes the lock for key "key-2"
    Then it is granted at once

  Scenario: A waiting process proceeds when the holder releases
    Given a private state directory
    And a real process holds the lock for key "key-1"
    When the holder releases the lock for key "key-1"
    Then this process can take the lock for key "key-1"

  Scenario: An unsafe key is refused
    Given a private state directory
    When a lock is requested for the key "../escape"
    Then it is refused with an error

  Scenario: A symlinked lock file is refused
    Given a private state directory
    And the lock file for key "key-1" is a symlink
    When a lock is requested for the key "key-1"
    Then it is refused with an error

  Scenario: Concurrent refresh and logout in separate processes never lose or resurrect a session
    Given a shared session store used by real processes
    And a real process has signed the person in
    When 3 real processes renew the session while 1 real process signs out
    Then every renewal either succeeded or reported that no session exists
    And the shared store ends with no session
