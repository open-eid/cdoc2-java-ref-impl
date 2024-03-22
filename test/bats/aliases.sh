#!/usr/bin/env bash

source variables.sh

if [ -z ${CDOC2_DIR+x} ]
then
  # two steps back to get root directory
  cd ../..
  export CDOC2_DIR=`pwd`
  export CDOC2_VER=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
  cd $TESTING_DIR
fi

if [ -z ${TEST_VECTORS+x} ]
then
  export TEST_VECTORS=${CDOC2_DIR}/test/testvectors
  cd $TESTING_DIR
fi

alias cdoc-cli='java -jar $CDOC2_DIR/cdoc20-cli/target/cdoc20-cli-$CDOC2_VER.jar'
export CDOC2_CMD="java -jar $CDOC2_DIR/cdoc20-cli/target/cdoc20-cli-$CDOC2_VER.jar"


cd $TESTING_DIR
