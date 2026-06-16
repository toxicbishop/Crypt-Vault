#!/bin/sh

git filter-branch --force --env-filter '
CORRECT_NAME="toxicbishop"
CORRECT_EMAIL="pranavarun19@gmail.com"

case "$GIT_COMMITTER_NAME" in
    *dependabot*|*github-advanced-security*)
        export GIT_COMMITTER_NAME="$CORRECT_NAME"
        export GIT_COMMITTER_EMAIL="$CORRECT_EMAIL"
        ;;
esac

case "$GIT_AUTHOR_NAME" in
    *dependabot*|*github-advanced-security*)
        export GIT_AUTHOR_NAME="$CORRECT_NAME"
        export GIT_AUTHOR_EMAIL="$CORRECT_EMAIL"
        ;;
esac
' --tag-name-filter cat -- --branches --tags
