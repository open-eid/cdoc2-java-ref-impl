#!/bin/bash

set -o xtrace
# git commit
# git tag
# git push
# mvn deploy
# docker deploy


CDOC2_VER=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

GIT_BRANCH=$(git branch --show-current)
GIT_REMOTE=$(git config --get-regexp "branch\.$GIT_BRANCH\.remote" | sed -e "s/^.* //")

# if mvn deploy is called
DEPLOY=true

if [[ "master" != "$GIT_BRANCH" ]]; then
  echo "Not on 'master' branch. You have 5 seconds to abort or the script will continue"
  sleep 5
fi

if [[ ${CDOC2_VER} == *"SNAPSHOT"* ]];then
    echo "cdoc2 is still on SNAPSHOT ${CDOC2_VER}. Did you run prepare_release.sh?"
    exit 2
fi

if ! grep -q ${CDOC2_VER} "CHANGELOG.md"; then
  echo "Can't find \"${CDOC2_VER}\" in CHANGELOG.md. Did you write CHANGELOG?"
  exit 3
fi

while getopts ":d" opt; do
  case ${opt} in
    d)
      echo "-d Dry-run mode. Deploy will not be performed."
      DEPLOY=false
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;;
  esac
done



export RELEASE_BRANCH="release_v$CDOC2_VER"
export RELEASE_TAG="v$CDOC2_VER"

git checkout -b "$RELEASE_BRANCH" || exit 1
git commit -a -m "Release cdoc2-java-ref-impl version $CDOC2_VER" || exit 1
git push "$GIT_REMOTE" -u "$RELEASE_BRANCH" || exit 1
git tag "$RELEASE_TAG" || exit 1
git push --tags $GIT_REMOTE "$RELEASE_TAG" || exit 1
echo "Created release branch $RELEASE_BRANCH"

# to delete branch, run:
# git checkout parent_branch
# git branch -D test_v1.2.0
# git push gitlab.ext -d test_v1.2.0


#deploy RELEASE modules
if [[ "$DEPLOY" = true ]]; then
  mvn deploy -DskipTests
  if [[ $? -ne 0 ]]; then
    echo "mvn deploy failed. If this was temporary error, it may be possible to recover by re-running 'mvn deploy -DskipTests'"
  fi
else
  echo "DEPLOY=$DEPLOY. To deploy Maven artifacts, run 'mvn deploy -DskipTests' on branch $RELEASE_BRANCH"
fi


# switch back to original branch
git checkout $GIT_BRANCH

echo "Created release branch $RELEASE_BRANCH"
echo "To merge squash back to your branch. Run"
echo "git merge --squash $RELEASE_BRANCH"
echo "git commit -m \"Squashed commit from $RELEASE_BRANCH\""
echo "git push $GIT_REMOTE $GIT_BRANCH"
