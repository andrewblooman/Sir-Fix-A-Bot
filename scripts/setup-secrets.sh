#!/usr/bin/env bash
#
# Create the Secret Manager secrets and load their values.
#
# Terraform creates the secret *containers* and the IAM bindings, but deliberately not the
# versions: a value passed through Terraform is written to state in plaintext, and state is
# usually more widely readable than the secret itself. This script sets the values out of band.
#
# Usage:
#   ./scripts/setup-secrets.sh <project-id>
#
# Re-running it adds a new version to each secret, which is how you rotate. References use
# `versions/latest`, and the running services re-read after their cache TTL (default 15 minutes),
# so a rotation needs no redeploy.

set -euo pipefail

PROJECT="${1:-}"
if [[ -z "$PROJECT" ]]; then
  echo "usage: $0 <project-id>" >&2
  exit 2
fi

# GitHub App key is a file; everything else is a prompted value.
SECRETS=(
  "sfb-wiz-client-id:Wiz service account client ID"
  "sfb-wiz-client-secret:Wiz service account client secret"
  "sfb-wiz-webhook-secret:Shared secret for the Wiz automation rule (x-sfb-token header)"
  "sfb-notion-token:Notion internal integration secret (ntn_...)"
  "sfb-anthropic-api-key:Anthropic API key (sk-ant-...)"
)

create_secret_if_missing() {
  local name="$1"
  if gcloud secrets describe "$name" --project="$PROJECT" >/dev/null 2>&1; then
    echo "  secret $name already exists"
  else
    gcloud secrets create "$name" --project="$PROJECT" --replication-policy=automatic
    echo "  created secret $name"
  fi
}

add_version_from_stdin() {
  # --data-file=- reads stdin verbatim. printf '%s' avoids the trailing newline that `echo` adds,
  # which is the most common way a secret silently fails to authenticate.
  local name="$1"
  gcloud secrets versions add "$name" --project="$PROJECT" --data-file=- >/dev/null
  echo "  added a new version to $name"
}

echo "Setting up Sir-Fix-A-Bot secrets in project ${PROJECT}"
echo

for entry in "${SECRETS[@]}"; do
  name="${entry%%:*}"
  description="${entry#*:}"

  echo "${name} — ${description}"
  create_secret_if_missing "$name"

  # -s so the value never appears on screen or in scrollback.
  read -r -s -p "  value (blank to skip): " value
  echo
  if [[ -n "$value" ]]; then
    printf '%s' "$value" | add_version_from_stdin "$name"
  else
    echo "  skipped"
  fi
  unset value
  echo
done

# The GitHub App private key is a multi-line PEM, so it comes from a file rather than a prompt.
GITHUB_KEY_SECRET="sfb-github-app-private-key"
echo "${GITHUB_KEY_SECRET} — GitHub App private key (.pem downloaded from the App settings)"
create_secret_if_missing "$GITHUB_KEY_SECRET"
read -r -p "  path to .pem (blank to skip): " pem_path
if [[ -n "$pem_path" ]]; then
  if [[ ! -f "$pem_path" ]]; then
    echo "  no such file: $pem_path" >&2
    exit 1
  fi
  gcloud secrets versions add "$GITHUB_KEY_SECRET" \
    --project="$PROJECT" --data-file="$pem_path" >/dev/null
  echo "  added a new version to $GITHUB_KEY_SECRET"
  echo
  echo "  Delete your local copy when you are done: rm ${pem_path}"
else
  echo "  skipped"
fi

echo
echo "Done. Reference these from the services as resource names, not values:"
echo
for entry in "${SECRETS[@]}"; do
  name="${entry%%:*}"
  printf '  projects/%s/secrets/%s/versions/latest\n' "$PROJECT" "$name"
done
printf '  projects/%s/secrets/%s/versions/latest\n' "$PROJECT" "$GITHUB_KEY_SECRET"
echo
echo "Use 'versions/latest' rather than a pinned version so rotation takes effect without a"
echo "redeploy. Verify a value with:"
echo "  gcloud secrets versions access latest --secret=sfb-notion-token --project=${PROJECT}"
