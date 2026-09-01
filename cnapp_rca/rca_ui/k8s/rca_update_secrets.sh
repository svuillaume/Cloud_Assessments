#!/bin/sh
# Updates the LW_* GitHub Secrets that rca-deploy.yml (the CD workflow) reads credentials
# from — a direct `gh secret set` call per variable, run locally. Deliberately NOT a
# workflow_dispatch input: GitHub Actions workflow inputs are shown in plain text on the run's
# summary page ("Triggered via workflow_dispatch" details), visible to anyone who can view the
# repo — for a PUBLIC repo (this one), that would publish FortiCNAPP credentials on every run.
# This script never touches a workflow run at all; values go straight from here to GitHub's
# encrypted secret store via the `gh` CLI.
#
# Usage:
#   ./rca_update_secrets.sh                  # pushes LW_ACCOUNT/LW_KEY_ID/LW_SECRET/
#                                             # LW_SUBACCOUNT from rca_ui/.env
#   LW_KEY_ID=FORTINET_NEW... ./rca_update_secrets.sh   # override just one value (e.g. after
#                                             # rotating a single credential) — env var wins
#                                             # over whatever's in .env for that key
#
# After updating, redeploy to actually pick up the new values:
#   gh workflow run rca-deploy.yml -R <repo> -f image_tag=<tag>
# (the CD workflow's "Sync FortiCNAPP credentials Secret" step reads these same GH Secrets
# fresh on every run, so nothing further is needed beyond re-running it)
set -eu

REPO="${REPO:-svuillaume/Cloud_Assessments}"

# This script lives in k8s/; .env lives one level up in rca_ui/ — same convention as
# deploy_k8s.sh.
cd "$(dirname "$0")/.."

echo "==> Updating LW_* secrets on $REPO"

for key in LW_ACCOUNT LW_KEY_ID LW_SECRET LW_SUBACCOUNT; do
  eval "override=\${$key:-}"
  if [ -n "$override" ]; then
    val="$override"
  elif [ -f .env ]; then
    val="$(grep -E "^${key}=" .env | head -1 | cut -d= -f2-)"
  else
    val=""
  fi

  if [ -n "$val" ]; then
    gh secret set "$key" -b "$val" -R "$REPO"
    echo "  updated $key"
  else
    echo "  skip $key (no value in .env or env override)"
  fi
done

echo
echo "Done. Redeploy to pick up the new values:"
echo "  gh workflow run rca-deploy.yml -R $REPO -f image_tag=<tag>"
