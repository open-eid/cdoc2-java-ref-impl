#!/usr/bin/env bash

# Set up remote repository and required branches manually before running extract_client_keys.sh script
export REMOTE_REPOSITORY=<SSH/to/cdoc2-capsule-server> # git@<git.url>:cdoc2/cdoc2-capsule-server.git
export SOURCE_BRANCH_NAME=<source branch name for fetching files>
export DESTINATION_BRANCH_NAME=<name of NEW destination branch>