#!/bin/bash

GIT_BRANCH=$(git branch --show-current)

if [[ "master" != "$GIT_BRANCH" ]]; then
  echo "Release will be made from branch $GIT_BRANCH."
  sleep 5
fi


if [[ -n $(git cherry -v) ]]; then
  echo "Detected unpushed commits. Exit"
  exit 1
fi

if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo "Uncommitted changes detected. Exit"
  exit 1
fi

while getopts "v:" opt; do
  case $opt in
    v)
      echo "Changing parent pom version to: $OPTARG" >&2
      mvn versions:set -DnewVersion="${OPTARG}" -DupdateMatchingVersions=false
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;;
  esac
done


# replace module -SNAPSHOT version with release version (non-SNAPSHOT)
mvn versions:set -DremoveSnapshot
mvn versions:set -DremoveSnapshot -pl cdoc2-schema
mvn versions:set -DremoveSnapshot -pl cdoc2-client
mvn versions:set -DremoveSnapshot -pl cdoc2-lib
mvn versions:set -DremoveSnapshot -pl cdoc2-cli
# build and install into local maven package repository
mvn install
