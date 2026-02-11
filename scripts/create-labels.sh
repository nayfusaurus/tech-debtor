#!/bin/bash
# Script to create labels for tech-debtor repository
# Usage: ./scripts/create-labels.sh

gh label create "analyzer" --color "0052CC" --description "Changes to analyzers" --force
gh label create "reporter" --color "0052CC" --description "Changes to reporters" --force
gh label create "cli" --color "5319E7" --description "CLI changes" --force
gh label create "tests" --color "5319E7" --description "Test changes" --force
gh label create "documentation" --color "0075CA" --description "Documentation changes" --force
gh label create "dependencies" --color "0366D6" --description "Dependency updates" --force
gh label create "ci" --color "D4C5F9" --description "CI/CD changes" --force
gh label create "config" --color "FEF2C0" --description "Configuration changes" --force
gh label create "python" --color "3572A5" --description "Python code changes" --force

echo "✅ Labels created successfully!"
echo "Note: Use --force to update existing labels"
