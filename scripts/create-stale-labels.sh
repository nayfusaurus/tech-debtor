#!/bin/bash
# Script to create stale-related labels for tech-debtor repository
# Usage: ./scripts/create-stale-labels.sh

gh label create "stale" --color "EEEEEE" --description "No recent activity" --force
gh label create "pinned" --color "D4C5F9" --description "Never mark as stale" --force
gh label create "help-wanted" --color "008672" --description "Extra attention is needed" --force
gh label create "good-first-issue" --color "7057FF" --description "Good for newcomers" --force
gh label create "security" --color "EE0701" --description "Security-related issue" --force
gh label create "work-in-progress" --color "FBCA04" --description "Work in progress" --force
gh label create "blocked" --color "D93F0B" --description "Blocked by external dependency" --force

echo "✅ Stale-related labels created successfully!"
