#!/usr/bin/env bash

source variables.sh


cd $BATS_HOME
git init
git submodule add https://github.com/bats-core/bats-core.git bats-core
cd bats-core
git checkout v1.10.0
cd ..

git submodule add https://github.com/bats-core/bats-support.git bats-support
cd bats-support
git checkout v0.3.0
cd ..

git submodule add https://github.com/bats-core/bats-assert.git bats-assert
cd bats-assert
git checkout v2.1.0
cd ..

git submodule add https://github.com/bats-core/bats-file.git bats-file
cd bats-file
git checkout v0.4.0


cd $TESTING_DIR
