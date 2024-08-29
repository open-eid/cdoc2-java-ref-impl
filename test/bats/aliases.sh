#!/usr/bin/env bash

source variables.sh

if [ -z ${CDOC2_DIR+x} ]
then
  # two steps back to get root directory
  cd ../..
  CDOC2_DIR=$(pwd)
  export CDOC2_DIR
  CDOC2_VER=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
  export CDOC2_VER
  cd cdoc2-cli || exit
  CDOC2_CLI_VER=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
  export CDOC2_CLI_VER
  (cd ..)
  cd "$TESTING_DIR" || exit
fi

if [ -z ${TEST_VECTORS+x} ]
then
  export TEST_VECTORS=${CDOC2_DIR}/test/testvectors
  export TEST_VECTORS_V_1_2=${CDOC2_DIR}/test/testvectors-v1.2
  export TEST_VECTORS_V_1_4=${CDOC2_DIR}/test/testvectors-v1.4
  cd "$TESTING_DIR" || exit
fi

alias cdoc-cli='java -jar $CDOC2_DIR/cdoc2-cli/target/cdoc2-cli-$CDOC2_CLI_VER.jar'
export CDOC2_CMD="java -jar $CDOC2_DIR/cdoc2-cli/target/cdoc2-cli-$CDOC2_CLI_VER.jar"


cd "$TESTING_DIR" || exit
