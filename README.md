<div align="center">

![Sir-Fix-A-Bot](assets/image.png)

# Sir-Fix-A-Bot

**Vulnerability Management Tool for Fixing Cloud Run Container Images**

[![CI](https://github.com/andrewblooman/Sir-Fix-A-Bot/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewblooman/Sir-Fix-A-Bot/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)

[![Built with Claude Agent SDK](https://img.shields.io/badge/Built%20with-Claude%20Agent%20SDK-D97757.svg)](https://code.claude.com/docs/en/agent-sdk)
[![Cloud Run](https://img.shields.io/badge/Runs%20on-Cloud%20Run-4285F4.svg?logo=googlecloud&logoColor=white)](https://cloud.google.com/run)
[![Wiz](https://img.shields.io/badge/Findings%20from-Wiz-00D4AA.svg)](https://www.wiz.io/)
[![Notion CMDB](https://img.shields.io/badge/CMDB-Notion-000000.svg?logo=notion&logoColor=white)](https://www.notion.com/)
[![PRs](https://img.shields.io/badge/Output-Pull%20Requests-181717.svg?logo=github&logoColor=white)](https://github.com/andrewblooman/Sir-Fix-A-Bot/pulls)

</div>

---

A Wiz finding against a Cloud Run service becomes a verified pull request against the service's
GitHub repo — without a human doing the lookup, the base-image research, or the Dockerfile surgery.

```text
Wiz webhook → intake (dedupe, enqueue) → Cloud Tasks → worker
   worker: enrich → resolve repo via Notion CMDB (MCP) → clone
         → Claude Agent SDK fix → post-condition gate → Cloud Build verify
         → push branch + open PR
```

Wiz knows a service is vulnerable but not which repository builds it; that mapping lives in a Notion
CMDB. Sir-Fix-A-Bot joins the two, then puts a coding agent to work under a fixed set of house rules
and refuses to open a PR until the image actually builds and the tests actually pass.

## House rules the agent works under

These are stated in the agent's prompt **and** enforced programmatically against the resulting diff
in `agent/gate.py`. Prompt adherence is not a security control, so every rule is checked twice.

| Rule | Why |
| --- | --- |
| **Runtime versions are patch-only** — `python:3.11` may become `python:3.11.14`, never `3.12` | A minor bump is a migration a team plans, not something to slip into a routine security patch |
| **No `USER` directive** — don't add one, don't create a user or group, leave existing ones alone | Workload identity is set at deploy time on this platform; an image-level `USER` conflicts with how these services actually run |
| **Multi-stage wherever there's a build phase** | The single biggest lever on CVE count — compilers, headers and package caches are most of what scanners flag, and none of it needs to ship |
| **Base images chosen, not defaulted** | Debian `-slim` for Python; Alpine only for pure-Python trees; distroless for the runtime stage |
| **OCI labels on the final stage**, with `revision`/`created` as build `ARG`s | A hardcoded SHA is wrong the moment it's committed, and wrong provenance is worse than none |
| **Tests added** when the touched code path has none | Using the repo's existing framework — no second test runner |

### Why not Alpine?

Alpine is the reflexive answer to "make the image smaller" and it's usually wrong for Python. Alpine
uses musl rather than glibc, so any package shipping a manylinux wheel — numpy, pandas, scipy,
psycopg2, cryptography, pillow, lxml — gets rebuilt from source. The image ends up larger, the build
slower, and the compilers dragged in to do it create new findings. The agent is told this explicitly,
because left alone it will reach for Alpine every time.

## Findings it can't fix

A finding that needs a minor version bump, or a transitive dependency that can't move without a
breaking upgrade, is reported as **blocked** and filed as a GitHub issue explaining what a human
needs to decide. That's a deliberate outcome, not a failure — the alternative is a PR that looks like
it fixes something and doesn't.

## Trust boundary

The agent edits the working tree and nothing else. It has no GitHub credentials, no push rights and
no Wiz client; `Bash` is restricted to an allowlist of programs with shell operators denied, so the
allowlist can't be escaped by chaining. Pushing the branch and opening the PR are deterministic
orchestrator steps that run only after the gate passes and the build is green.

This matters because Wiz finding text — CVE descriptions, package metadata — is attacker-influenceable
in principle. The agent is treated as untrusted input handling untrusted input.

## Running it

```bash
python3.14 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest

# main development loop: full pipeline against a real finding, nothing pushed
python -m sir_fix_a_bot.cli fix --finding-id <id> --dry-run
```

### Deployment shape

Both components run on Cloud Run. The worker is a *service* rather than a Job because Cloud Tasks
does HTTP push with OIDC and gives retry and backoff for free.

| | intake | worker |
| --- | --- | --- |
| Concurrency | 80 | **1** — the agent owns a worktree and shells out |
| Timeout | 30s | 1800s |
| Memory | 512 MiB | **4 GiB** — Cloud Run's filesystem is tmpfs and counts against this |
| Execution environment | gen2 | gen2 — gen1's gVisor breaks `git` and the Node subprocess |

The real ceiling is **Cloud Tasks' 30-minute max dispatch deadline**, not Cloud Run's 60-minute
request timeout. Past it, Tasks abandons the request and retries while the worker is still going,
which produces duplicate PRs. The agent and build budgets are sized to stay well inside it.

## Configuration

All settings are `SFB_`-prefixed environment variables (see `config.py` and `.env.example`).

Notion's *hosted* MCP server is OAuth-browser-only and unusable headless, so the CMDB lookup runs
against a self-hosted `@notionhq/notion-mcp-server` over stdio with an internal integration token.

## Credentials

Six secrets live in **Secret Manager**: Wiz client ID and secret, the Wiz webhook shared secret,
the Notion integration token, the GitHub App private key, and the Anthropic API key.

Every secret-bearing setting accepts *either* a literal value (local development) *or* a Secret
Manager resource name. In production you set the resource name, which is not itself sensitive:

```bash
SFB_NOTION_TOKEN=projects/my-project/secrets/sfb-notion-token/versions/latest
```

`resolve_secret()` reads the value at the point of use, so no secret material appears in the Cloud
Run environment, in Terraform state, or in a `.env` file. Resolution is lazy, which also means a
missing IAM binding surfaces as a clear runtime error rather than a service that won't start.

### Setting them up

```bash
cd deploy/terraform && terraform apply     # creates the secret containers + IAM bindings
../../scripts/setup-secrets.sh my-project  # loads the values, prompting for each
```

Terraform deliberately creates the secret *containers* but not the *versions* — a value passed
through Terraform is written to state in plaintext, and state is usually more widely readable than
the secret itself.

### Rotation

Re-run `setup-secrets.sh` to add a new version. References point at `versions/latest` and resolved
values are cached for 15 minutes (`SFB_SECRET_CACHE_TTL_S`), so a rotation takes effect without a
redeploy. The cache has a TTL rather than being unbounded specifically so that rotating *because of
a compromise* actually evicts the old credential — a Cloud Run instance can otherwise serve for
hours.

### Least privilege

Three service accounts, so the blast radius of each is bounded:

| Identity | Can read | Notes |
| --- | --- | --- |
| `sfb-intake` | Wiz webhook secret only | Cannot open a PR — no GitHub key, no Anthropic key |
| `sfb-worker` | All six | Runs the agent and opens pull requests |
| `sfb-tasks-invoker` | Nothing | Exists only to mint OIDC tokens for the worker |

The GitHub credential is a **GitHub App**, not a PAT: tokens are minted per repository and expire
within the hour. They are handed to git through `GIT_CONFIG_*` rather than embedded in the remote
URL, so no token persists into `.git/config` where the agent's own `Read` tool could find it.

## Licence

[Apache 2.0](LICENSE)
