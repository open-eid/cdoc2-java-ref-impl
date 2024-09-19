#!/bin/bash

GIT_BRANCH=$(git branch --show-current)

CHECK_FOR_CLEAN_BRANCH=true

while getopts "v:c" opt; do
  case $opt in
    c)
      echo "Not checking for clean branch (-c)"
      CHECK_FOR_CLEAN_BRANCH=false
      ;;
    v)
      echo "Changing parent pom version to: $OPTARG"
      mvn versions:set -DnewVersion="${OPTARG}" -DupdateMatchingVersions=false
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;;
  esac
done

if [[ "$CHECK_FOR_CLEAN_BRANCH" = true ]]; then
  echo "Checking for clean git checkout. Disable with '-c'"
  if [[ "master" != "$GIT_BRANCH" ]]; then
    echo "Not on 'master' branch. You have 5 seconds to abort."
    sleep 5
  fi

  if [[ -n $(git cherry -v) ]]; then
    echo "Detected unpushed commits. Exit"
    exit 1
  fi

  if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
    echo "Uncommited changes detected. Exit"
    exit 1
  fi
else
  echo "Not checking for clean branch CHECK_FOR_CLEAN_BRANCH=$CHECK_FOR_CLEAN_BRANCH"
fi


# replace module -SNAPSHOT version with release version (non-SNAPSHOT)
mvn versions:set -DremoveSnapshot
mvn versions:set -DremoveSnapshot -pl cdoc2-schema
mvn versions:set -DremoveSnapshot -pl cdoc2-client
mvn versions:set -DremoveSnapshot -pl cdoc2-lib
mvn versions:set -DremoveSnapshot -pl cdoc2-cli
# build and install into local maven package repository
mvn install
