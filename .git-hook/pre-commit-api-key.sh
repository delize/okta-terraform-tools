#!/bin/bash

# Define patterns for common API keys (AWS, Google, Stripe, GitHub, Slack, Facebook, Mailchimp, Okta, Terraform, etc.)
PATTERNS=(
    "AKIA[0-9A-Z]{16}"  # AWS Access Key ID
    "AIza[0-9A-Za-z-_]{35}"  # Google API Key
    "sk_live_[0-9a-zA-Z]{24}"  # Stripe Live Secret Key
    "ghp_[0-9a-zA-Z]{36}"  # GitHub Personal Access Token
    "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"  # Slack Token
    "EAACEdEose0cBA[0-9A-Za-z]+"  # Facebook Access Token
    "[0-9a-f]{32}-us[0-9]{1,2}"  # Mailchimp API Key

    # Okta API Tokens
    "00[0-9a-zA-Z]{38}"  # Okta API Key (starts with "00" followed by 38 alphanumeric characters)

    # Terraform Cloud/Enterprise API Tokens
    "tfe.[0-9a-zA-Z]{35}"  # Terraform Cloud API Key (tfe.xxxxxx...)

    # Generic API Key formats (adjust based on your security needs)
    "[A-Za-z0-9]{32}"  # Generic 32-character API keys
    "[A-Za-z0-9]{40}"  # Generic 40-character API keys
    "[A-Za-z0-9]{64}"  # Generic 64-character API keys
)

# Check staged files for API keys
FILES=$(git diff --cached --name-only --diff-filter=ACM)

for FILE in $FILES; do
    # Skip binary files
    if file "$FILE" | grep -qE 'binary'; then
        continue
    fi

    for PATTERN in "${PATTERNS[@]}"; do
        if grep -E -q "$PATTERN" "$FILE"; then
            echo "❌ Commit rejected: API key detected in '$FILE'"
            echo "🔍 Found match for: $PATTERN"
            exit 1
        fi
    done
done

echo "✅ No API keys found. Proceeding with commit."
exit 0