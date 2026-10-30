# Agent Instructions

## Project management with Kanbus

Use Kanbus for task management.
Why: Kanbus task management is MANDATORY here; every task must live in Kanbus.
When: Create/update the Kanbus task before coding; close it only after the change lands.
How: See CONTRIBUTING_AGENT.md for the Kanbus workflow, hierarchy, status rules, priorities, command examples, and the mistakes to avoid. Never inspect project/ or issue JSON directly (including with cat or jq); use Kanbus commands only.
Performance: Prefer kbs (Rust) when available; kanbus (Python) is equivalent but slower.
Warning: Editing project/ directly violates The Way. Do not read or write anything in project/; work only through Kanbus.
Git / PR policy: Rules for product-code commits, branch names, pull requests, and human approval live in this repository's AGENTS.md (outside this Kanbus section). CONTRIBUTING_AGENT.md covers Kanbus board mechanics such as `kbs commit`; follow AGENTS.md for product code and git workflow.


## What this project is

`cli-login` is the one CLI login shared by Anthus products (Cyclotron, Papyrus, Auritus, and later Chatticus). It
holds three parts: a Python library for the CLI side, a broker deployed once per product deployment, and a
language-neutral protocol with conformance specs. Read [docs/design.md](docs/design.md) first.

## Rules that matter here

- **This repository is public.** Never commit account ids, user pool ids, client ids, product domains, tokens,
  secrets or real email addresses. Each product supplies its own values through its discovery data. Examples use
  placeholders such as `https://app.example.test`.
- **Products stay separate.** Every stored key carries the product namespace, and a store refuses a key outside
  the namespace it was opened with. One product never reads, refreshes or revokes another product's credentials.
- **Fail closed.** No plaintext fallback for any secret, ever. A missing, locked or unusable store is an error with
  recovery guidance.
- **Never replay an uncertain mutation.** Only token operations are retried.
- **Specs first.** Every behaviour change ships with Gherkin specs and unit specs beside the module. Specs use fake
  providers, stores and brokers; no network or credentials in specs. Live proof is recorded separately.
- **Protocol changes are versioned.** A change to the broker protocol bumps the major version, and the broker's
  answers carry it.
- **Do not print, log or commit secrets.** Status and errors redact every token.

## Git workflow

Git Flow: branch from `develop`, open a pull request to `develop`, merge with a merge commit once CI is green.
Promotion to `main` is a pull request from `develop`. Kanbus board changes are committed on `develop` with
`kbs commit` and pushed, with no pull request. Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`).
