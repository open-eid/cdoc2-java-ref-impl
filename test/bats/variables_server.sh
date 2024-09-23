#!/usr/bin/env bash

# testing directory
export TESTING_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export BATS_HOME=$TESTING_DIR/target
mkdir -p $BATS_HOME

alias bats='$BATS_HOME/bats-core/bin/bats'