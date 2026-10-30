# cli-login

One CLI login for every Anthus product, without long-lived keys.

- **Sign in on this machine or from another device.** `login --remote` prints a URL and a short matching code; you
  approve on your phone or laptop, and the waiting CLI receives its own renewable session. No access key, pasted
  code or token passes through chat.
- **Secure storage, never plain text.** macOS Keychain, Linux Secret Service, the Linux kernel keyring, a
  memory-only agent for cloud machines, or Windows Credential Manager.
- **Renewal and honest logout.** Sessions renew with the refresh token. Logout revokes it, and says so when it
  could not.
- **A broker per deployment.** A small Lambda function and DynamoDB table that hands one authorization code to the
  one CLI that asked for it, and never holds a token.

## Install

```bash
pip install anthus-cli-login
pip install "anthus-cli-login[linux]"   # adds Secret Service support on Linux
```

Requires Python 3.10 or newer.

## Where sessions are stored

Sessions live only in a secure store, tried in this order. There is no plaintext fallback: if nothing is
usable, the tool fails with the exact steps to fix it.

| Platform | Store (in order) | Lasts |
| --- | --- | --- |
| macOS | Keychain (service name = the product namespace, so existing sessions keep working) | until logout |
| Linux | 1. Secret Service (D-Bus), needs `pip install "anthus-cli-login[linux]"` and an unlocked keyring; 2. kernel keyring; 3. the memory agent | keyring: until logout; kernel keyring: until reboot, or the persistent keyring's expiry (3 days from last use by default); agent: until it stops |
| Windows | Credential Manager (`<namespace>/<key>`; values over 2,560 bytes are chunked) | until logout |

The memory agent is not available on Windows in this version. Set `ANTHUS_CLI_LOGIN_STORE` to `keychain`,
`secret-service`, `kernel-keyring`, `agent` or `credential-manager` to choose a store explicitly (for operators
and tests). Any other value is refused.

### Cloud machines and containers

A cloud machine usually has no desktop keyring, and Docker's default seccomp profile blocks the kernel keyring
calls. Start the memory agent once per product, then sign in again:

```bash
python -m anthus_cli_login.stores.agent serve --namespace <product-namespace> --background
python -m anthus_cli_login.stores.agent status --namespace <product-namespace>
python -m anthus_cli_login.stores.agent stop   --namespace <product-namespace>
```

A product mounts the same functions (`stores.agent.serve`, `start_background`, `status`, `stop`, `main`) under
its own CLI name, such as `<product> auth agent`. The agent holds sessions in memory only, behind a 0600 Unix
socket in a 0700 directory under the product's state directory (`~/.config/anthus-cli-login/<namespace>/agent`,
or the socket named by `ANTHUS_CLI_LOGIN_AGENT_SOCKET`, which must sit in a private directory and be short
enough for a Unix socket). It checks the caller's user id on every connection, disables core dumps, and keeps
nothing on disk. After it stops, or the machine restarts, sign in again. Processes of the same user can use it,
as with ssh-agent.

### Recovering from each failure

- **"No Secret Service is reachable"**: no D-Bus session or keyring daemon. On a server, use the memory agent.
- **"Secret Service keyring is locked"**: unlock it by signing in to the desktop session, then retry.
- **"anthus-cli-login[linux]"**: the optional dependency is missing; `pip install "anthus-cli-login[linux]"`.
- **"kernel keyring is unavailable"**: the kernel or container blocks `add_key`/`keyctl`. Use the memory agent,
  or run the container with a seccomp profile that allows them.
- **"The memory agent is not running"**: run the `serve` command shown in the message, then sign in again.
- **Agent socket refused**: the directory or socket is not owned by you or not private; fix the mode (0700) or
  remove the stale path and restart the agent.
- **"The stored session is damaged"** (Windows): run the login command again to replace it.
- **Credential Manager errors on Windows**: sign in to Windows normally (not a restricted service account) and
  retry.

Status: see [docs/design.md](docs/design.md).

## Releasing (maintainers)

Pushing to `main` (a pull request from `develop`) runs python-semantic-release on the conventional commits:
`feat:` and `fix:` (or a breaking change) bump the version in `pyproject.toml`, tag `vX.Y.Z` and create a GitHub
release; other commits release nothing. The `pypi` job then builds the sdist and wheel and publishes them with
OIDC trusted publishing, so no PyPI token is stored anywhere. Publishing needs a PyPI trusted publisher, registered
by the PyPI account owner: project `anthus-cli-login`, owner `AnthusAI`, repository `cli-login`, workflow
`release.yml`, environment `pypi`. The workflow's `pypi` environment must also exist in the repository settings.

The library targets Cognito user pools with the authorization-code flow and PKCE. Each product supplies its own
issuer, client and endpoints; this repository holds none.

## License

MIT
