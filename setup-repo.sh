#!/bin/bash
# Run this once to create the GitHub repo and push the code.
# Requires: gh CLI authenticated (run `gh auth login` first if needed)

set -e

REPO="polarpoint-io/tenable-exporter"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "→ Creating private repo $REPO..."
gh repo create "$REPO" --private --description "Prometheus exporter for Tenable.io metrics"

echo "→ Initialising git..."
cd "$DIR"
git init
git add .
git commit -m "Initial commit: tenable-exporter"

echo "→ Pushing to GitHub..."
git remote add origin "https://github.com/$REPO.git"
git push -u origin main

echo "✓ Done! Repo: https://github.com/$REPO"
