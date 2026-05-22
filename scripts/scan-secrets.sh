#!/usr/bin/env bash
set -euo pipefail

echo "Scanning staged files for secrets..."

# Extended regex patterns (compatible with macOS grep -E)
PATTERNS=(
  'AKIA[0-9A-Z]{16}'                              # AWS Access Key ID
  'sk_live_[a-zA-Z0-9]{24}'                       # Stripe live key
  'ghp_[a-zA-Z0-9]{36}'                           # GitHub personal access token
  'xox[bpas]-[a-zA-Z0-9\-]{10,}'                  # Slack token
  'BEGIN (RSA|EC) PRIVATE KEY'                    # Private keys
  'password[[:space:]]*=[[:space:]]*["\x27][^"\x27]{8,}["\x27]'  # Hardcoded passwords
)

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
  echo "No staged files to scan."
  exit 0
fi

FOUND=0
for file in $STAGED_FILES; do
  [ -f "$file" ] || continue

  for pattern in "${PATTERNS[@]}"; do
    if grep -En "$pattern" "$file" 2>/dev/null; then
      echo "ALERT: Potential secret in $file (pattern: $pattern)"
      FOUND=1
    fi
  done
done

if [ "$FOUND" -eq 1 ]; then
  echo ""
  echo "COMMIT BLOCKED: Potential secrets detected."
  echo "Remove the secrets or add the files to .gitignore."
  exit 1
fi

echo "Scan complete — no secrets found."
exit 0
