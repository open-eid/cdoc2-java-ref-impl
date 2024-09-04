#!/usr/bin/env bash

source variables.sh

if [ -z ${CDOC2_DIR+x} ]
then
  # two steps back to get root directory
  cd ../..
  export CDOC2_DIR=`pwd`
  export CDOC2_VER=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
  cd cdoc2-cli
  export CDOC2_CLI_VER=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
  cd ..
  cd $TESTING_DIR
fi

if [ -z ${TEST_VECTORS+x} ]
then
  export TEST_VECTORS=${CDOC2_DIR}/test/testvectors
  export TEST_VECTORS_V_1_2=${CDOC2_DIR}/test/testvectors-v1.2
  cd $TESTING_DIR
fi

alias cdoc-cli='java -jar $CDOC2_DIR/cdoc2-cli/target/cdoc2-cli-$CDOC2_CLI_VER.jar'
export CDOC2_CMD="java -jar $CDOC2_DIR/cdoc2-cli/target/cdoc2-cli-$CDOC2_CLI_VER.jar"


cd $TESTING_DIR

export CDOC2_CONFIG=$CDOC2_DIR/cdoc2-cli/config

export TEST_RESULTS_DIR=$TESTING_DIR/target/results
export FILE_FOR_ENCRYPTION=$CDOC2_DIR/README.md
export DECRYPTED_FILE=$TEST_RESULTS_DIR/README.md
export CDOC2_CONTAINER_NAME="cdoc_test_container.cdoc"
export CDOC2_CONTAINER=$TEST_RESULTS_DIR/$CDOC2_CONTAINER_NAME
export CLI_KEYS_DIR=$CDOC2_DIR/cdoc2-cli/keys
export PW="myPlainTextPassword"
export PW_LABEL="passwordlabel"
export PASSWORD_WITH_LABEL="$PW_LABEL:$PW"
export SECRET="base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE="
export SECRET_LABEL="mylabel"
export SECRET_WITH_LABEL="$SECRET_LABEL:$SECRET"
