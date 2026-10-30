# Design

Status: **proposed**. Nothing is built or released yet.

## Goal

An agent on a cloud machine with no browser runs `<product> login --remote`. It prints a URL and a short
matching code, and waits. The person opens the URL on another device, signs in as usual, checks the code, and
approves. The CLI then holds its own renewable session.

No access key, pasted code or token passes through chat, and no long-lived key is needed anywhere. The same
library also signs in on a machine that has a browser, stores sessions securely on every platform, renews them,
and logs out honestly.

## Products stay separate

Several products use this library, and each stays separate:
- its own key namespace in the secure store;
- its own Cognito client;
- its own discovery data;
- its own sessions.

One product never reads, refreshes or revokes another's credentials, and no single login covers two products.
The library enforces this: the product namespace is part of every stored key, and a store refuses a key outside
the namespace it was opened with.

This repository holds no product values: no account ids, pool ids, client ids, domains or secrets. A product
supplies them through its discovery data.

## The parts

### 1. The Python library

A product describes one **target**:
- the issuer and client id;
- the authorization and token endpoints;
- the API origin;
- the broker endpoint and callback URI;
- its product namespace;
- the binding it checks, such as a site, or a lab with an account on top.

The library does the rest:

- **Local sign-in.** PKCE (S256), a loopback callback on a free port, state and nonce, and the token
  exchange. It checks each token's issuer, client, `token_use`, expiry and nonce.
- **Remote sign-in.** It calls the broker's `/start`, prints the approval URL and matching code, polls `/poll`
  at the interval given, waits longer on `slow_down`, and exchanges the code (see the protocol below).
- **Secure stores**, tried in this order, each failing closed with recovery guidance and never falling back to
  plain text:
  1. macOS Keychain;
  2. Linux Secret Service (D-Bus);
  3. the Linux kernel keyring, after a probe, because Docker's default seccomp profile blocks `keyctl` and
     `add_key`;
  4. the memory agent;
  5. Windows Credential Manager, where a blob is at most 2,560 bytes, so it stores only the refresh token.

  Backends are named explicitly, so a library such as `keyring` can never choose a plaintext backend on its own.
  A product may keep an existing Keychain service name, so its existing sessions survive.
- **The memory agent.** It runs as `<product> auth agent`, with `--status` and `stop`, in the style of
  ssh-agent. It holds refresh tokens in memory only, behind a 0600 Unix socket, never on disk, one agent per
  product. After a restart, the person approves again.
- **Locks.** One cross-platform lock per stored key (`fcntl` on POSIX, `LockFileEx` on Windows), never a global
  lock.
- **Renewal.** It refreshes shortly before the access token expires, while holding the key's lock, so
  concurrent processes never lose a rotated refresh token. On `invalid_grant` it ends the session with recovery
  guidance. On a network error, 429 or 5xx, it keeps the session and retries. Only token operations are retried,
  never a product's mutation whose outcome is uncertain.
- **Logout.** It deletes the local secret and revokes the refresh token at `/oauth2/revoke`. It reports a
  failed or offline revocation rather than hiding it, and says that an access token the API already accepted
  stays valid until it expires.
- **Status and whoami.** They redact every token, and keep what is cached locally apart from what the server
  confirms.
- **Commands.** Optional ready-made `login [--remote]`, `status`, `whoami`, `logout` and `auth agent`
  subcommands that a product mounts under its own CLI name.

### 2. The broker

Cognito has no RFC 8628 device flow, and a flow that has the person paste a code back into the terminal is
ruled out. So each product deployment runs one broker that hands one authorization code to the one CLI that
asked for it.

The broker is a deployable unit: a Python Lambda function behind a function URL, a DynamoDB table with TTL, and
a CloudFormation template.

- **Routes.** It serves `POST /start` and `POST /poll`, and the pages `/cli/approve` and `/cli/callback`. The
  product routes `/cli/*` on its own domain to it, through an Amplify reverse-proxy rewrite or a CloudFront
  behavior, so the approval page and its CSRF cookie belong to the product's domain.
- **Fallback.** If a product's routing cannot pass the broker's `Set-Cookie` header and the caller's address
  through, the product serves the two pages itself, using the library's page handlers.
- **Safety.** The broker never holds a token. It rate-limits each caller on `/start` and `/poll`, and sends
  `slow_down` to a CLI that polls too fast.

### 3. The protocol and conformance specs

The protocol below is language-neutral. Gherkin features check a broker and a client against it, so a CLI in
another language implements the client from the protocol and runs the same features.

## The protocol

1. **Start.** The CLI makes a PKCE verifier V and a poll secret P, and keeps both in memory. It sends
   `POST /start` with:
   - the client id;
   - the target;
   - `code_challenge = S256(V)`;
   - `sha256(P)`;
   - a requester label (host name, CLI version and an optional note).

   The broker answers with:
   - a transaction id T (128 random bits);
   - a matching code (eight characters from an unambiguous alphabet);
   - the approval URL `https://<product-domain>/cli/approve?t=T`;
   - a poll interval;
   - an expiry about 10 minutes away;
   - the protocol version.
2. **Approve.** The approval page shows the requester, the matching code, the target, and what the session
   will be able to do. It asks the person to compare the code with the one the agent reported before approving.

   Approve sends the browser to Cognito `/oauth2/authorize` with:
   - the transaction's `code_challenge`;
   - `redirect_uri=https://<product-domain>/cli/callback`;
   - `state` = T plus a CSRF nonce bound to a short-lived cookie.

   Deny and cancel are recorded on the transaction.
3. **Callback.** `/cli/callback` checks the state against the cookie and stores the authorization code on T.
4. **Poll.** The CLI polls `POST /poll` with T and P. The broker compares `sha256(P)`. It answers pending,
   denied, expired or `slow_down`, and, once the code is there, returns it exactly once, through a conditional
   delete, so two polls at the same moment cannot both receive it.
5. **Exchange.** The CLI exchanges the code with V at the Cognito token endpoint and verifies the tokens itself.

What this guarantees:
- **The broker never holds a token**, and the code it holds for a few seconds is useless without V.
- **The URL cannot redeem anything without P.**
- **Each transaction is single use, expires, and is bound to issuer, client and target.** A replayed, expired,
  denied or substituted transaction yields nothing.
- **Phishing is the remaining risk**, as in every device flow: someone could send the URL to another person.
  The requester label and the matching code are the defence.

## A product's API

The CLI calls the product's API with `Authorization: Bearer <access token>`. The API verifies the token as it
would for a browser session. A request that carries both a cookie and a bearer token is refused.

## Evidence that renewal works

Every release reports three things separately:
1. **Specs with a simulated clock:** more than 24 hours, fresh processes, concurrent refresh, revocation.
2. **The provider's settings:** each client's token settings, read and recorded.
3. **A real run:** a cloud session logged in with `--remote` that keeps working for 24 hours or more of elapsed
   time.

## Versions

The library is a Python package released from this repository, and each product pins an exact version. A
change to the protocol bumps the major version. A broker and a client must speak the same major version, and the
broker's answers carry it.

## Order of work

1. **Move an existing CLI login into the library** (the first adopter's), keeping its behaviour and stored key
   names.
2. **Build the new parts once, here:** the Linux and Windows stores, the memory agent, the locks, remote
   sign-in, and the broker. Prove the broker, including the `/cli/*` routing, on one test deployment.
3. **Products adopt the released library one at a time.** Each adoption needs its own live changes: a callback
   URL on its Cognito client, its broker deployed, and the `/cli/*` route on its domain.
