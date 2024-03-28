#!/usr/bin/env bash

source variables.sh
source aliases.sh

setup() {
  load "target/bats-support/load"
  load "target/bats-assert/load"
  load "target/bats-file/load"
  DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" >/dev/null 2>&1 && pwd )"
  PATH="$DIR:$PATH"
}


TEST_RESULTS_DIR=$TESTING_DIR/target/results
mkdir -p $TEST_RESULTS_DIR
FILE_FOR_ENCRYPTION=$CDOC2_DIR/README.md
FILE_FOR_ENCRYPTION2=$CDOC2_DIR/pom.xml
DECRYPTED_FILE=$TEST_RESULTS_DIR/README.md
CDOC2_CONTAINER_NAME="cdoc_test_container.cdoc"
CDOC2_CONTAINER=$TEST_RESULTS_DIR/$CDOC2_CONTAINER_NAME
CLI_KEYS_DIR=$CDOC2_DIR/cdoc2-cli/keys
PASSWORD_WITH_LABEL="passwordlabel:myPlainTextPassword"
SECRET_WITH_LABEL="mylabel:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE="

#bats run doesn't support alias
#https://github.com/bats-core/bats-core/issues/259
run_alias() {
	shopt -s expand_aliases
	source "aliases.sh"
	eval "$*"
}

@test "Starting..." {
  echo "# Preparing tests...">&3
}

@test "Testing directory is initialized" {
  run $TESTING_DIR
  echo "# $TESTING_DIR">&3
  assert_output --partial '/test/bats'
}

@test "CDOC2 version is found" {
  run echo $CDOC2_VER
  echo "# $CDOC2_VER">&3
  assert_output --partial 'SNAPSHOT'
}

@test "preparing: assert BATS_HOME value exists" {
  run ${BATS_HOME}
  echo "# BATS_HOME=$BATS_HOME">&3
  assert_output --partial '/test/bats/target'
}

@test "preparing: assert bats helpers are installed" {
  run ${BATS_HOME}/bats-core
  assert_output --partial '/test/bats/target/bats-core'
}

@test "preparing: assert alias bats value exists" {
  run alias bats
  assert_output --partial '/bats-core/bin/bats'
}

@test "preparing: assert TEST_VECTORS value exists" {
  run ${TEST_VECTORS}
  assert_output --partial '/test/testvectors'
}

@test "preparing: cdoc-cli is available" {
  run $CDOC2_CMD
  assert_output --partial 'cdoc2-cli is a command line interface for cdoc2 library'
}

@test "test1: successfully encrypt CDOC2 container with EC" {
  local cdoc_file="ec_simple.cdoc"
  run run_alias cdoc-cli create -f $TEST_RESULTS_DIR/$cdoc_file \
          -c $CLI_KEYS_DIR/cdoc2client-certificate.pem $FILE_FOR_ENCRYPTION

  assertSuccessfulExitCode
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdoc_file"

  # ensure encrypted container can be decrypted successfully
  run run_alias cdoc-cli decrypt -f $$TEST_RESULTS_DIR/$cdoc_file -k $CLI_KEYS_DIR/cdoc2client.pem -o $TEST_RESULTS_DIR
  assertSuccessfulDecryption

  rm -f $TEST_RESULTS_DIR/$cdoc_file
}

@test "test2: successfully encrypt CDOC2 container with RSA" {
  local cdoc_file="rsa_simple.cdoc"
  run run_alias cdoc-cli create -f $TEST_RESULTS_DIR/$cdoc_file \
          -p $CLI_KEYS_DIR/rsa_pub.pem $FILE_FOR_ENCRYPTION

  assertSuccessfulExitCode
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdoc_file"

  # ensure encrypted container can be decrypted successfully
  run run_alias cdoc-cli decrypt -f $$TEST_RESULTS_DIR/$cdoc_file -k $CLI_KEYS_DIR/rsa_priv.pem -o $TEST_RESULTS_DIR

  assertSuccessfulDecryption

  rm -f $TEST_RESULTS_DIR/$cdoc_file
}

@test "test3: successfully encrypt CDOC2 container with password" {
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode
  assert_output --partial "Created $CDOC2_CONTAINER"
}

@test "test4: successfully decrypt CDOC2 container from test1 with password" {
  run run_alias cdoc-cli decrypt -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL --output $TEST_RESULTS_DIR
  assertSuccessfulExitCode
  assert_output --partial "Decrypting $CDOC2_CONTAINER"
  assertSuccessfulDecryption

  removeEncryptedCdoc
}

@test "test5: successfully encrypt CDOC2 container with few files" {
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL $FILE_FOR_ENCRYPTION $FILE_FOR_ENCRYPTION2
  assertSuccessfulExitCode

  removeEncryptedCdoc
}

@test "test6: fail to encrypt CDOC2 container with password if it's validation has failed" {
  password="passwordlabel:short";
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER -pw $password $FILE_FOR_ENCRYPTION
  assertFailure
}

@test "test7: fail to decrypt CDOC2 container with wrong decryption key type" {
  # encrypt with secret key
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER --secret $SECRET_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode

  # try to decrypt with password
  run run_alias cdoc-cli decrypt -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL --output $TEST_RESULTS_DIR
  assertFailure

  removeEncryptedCdoc
}

@test "test8: successfully encrypt CDOC with two keys and decrypt with one of them" {
  # encrypt with secret key and password
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER --secret $SECRET_WITH_LABEL -pw $PASSWORD_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode

  # decrypt with secret
  run run_alias cdoc-cli decrypt -f $CDOC2_CONTAINER --secret $SECRET_WITH_LABEL --output $TEST_RESULTS_DIR
  assertSuccessfulExitCode
  assert_output --partial "Decrypting $CDOC2_CONTAINER"
  assertSuccessfulDecryption

  removeEncryptedCdoc
}

@test "test9: successfully re-encrypt CDOC2 container" {
  # prepare encrypted container for further re-encryption
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER --secret $SECRET_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode

  # create new directory for re-encrypted container
  new_directory=$TEST_RESULTS_DIR/reencrypt
  mkdir -p $new_directory

  run run_alias cdoc-cli re -f $CDOC2_CONTAINER --encpassword $PASSWORD_WITH_LABEL --secret $SECRET_WITH_LABEL --output $new_directory
  assertSuccessfulExitCode

  # ensure re-encrypted container can be decrypted successfully
  run run_alias cdoc-cli decrypt -f $new_directory/$CDOC2_CONTAINER_NAME -pw $PASSWORD_WITH_LABEL --output $new_directory
  assertSuccessfulExitCode
  assert_output --partial "Decrypting $new_directory/$CDOC2_CONTAINER_NAME"
  assertSuccessfulDecryption

  # remove new directory and all created files in it
  rm -f $new_directory/$CDOC2_CONTAINER_NAME
  rm -f $new_directory/README.md
  rm -d $new_directory

  removeEncryptedCdoc
}

@test "test10: fail re-encryption within the same directory" {
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER --secret $SECRET_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode

  run run_alias cdoc-cli re -f $CDOC2_CONTAINER --encpassword $PASSWORD_WITH_LABEL --secret $SECRET_WITH_LABEL --output $TEST_RESULTS_DIR
  assertFailure

  removeEncryptedCdoc
}

@test "All tests were executed." {
  echo "All tests were executed."
}

assertSuccessfulExitCode() {
  successfulExitCode=0
  assert_success
  assert_equal $status $successfulExitCode
}

assertSuccessfulDecryption() {
  input_filename=$(basename "$FILE_FOR_ENCRYPTION")
  output_filename=$(basename "$DECRYPTED_FILE")
  assert_equal $output_filename $input_filename

  rm -f $DECRYPTED_FILE
}

assertFailure() {
  failureExitCode=1
  assert_equal $status $failureExitCode
}

removeEncryptedCdoc() {
  rm -f $CDOC2_CONTAINER
}

# removes created temporary files within testing
teardown_file() {
  rm -d $TEST_RESULTS_DIR
}
