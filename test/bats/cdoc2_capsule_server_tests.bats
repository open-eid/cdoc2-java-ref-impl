#!/usr/bin/env bash


setup() {
  load "target/bats-support/load"
  load "target/bats-assert/load"
  load "target/bats-file/load"
  DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" >/dev/null 2>&1 && pwd )"
  PATH="$DIR:$PATH"

  # check if expect is installed
  if command -v expect > /dev/null 2>&1; then
      HAS_EXPECT=true
  else
      HAS_EXPECT=false
  fi

}


mkdir -p "$TEST_RESULTS_DIR"


#bats run doesn't support alias
#https://github.com/bats-core/bats-core/issues/259
run_alias() {
	shopt -s expand_aliases
	source "aliases_server.sh"
	eval "$*"
}

@test "Starting..." {
  echo "# Preparing capsule-server tests...">&3
}

@test "Testing directory is initialized" {
  run $TESTING_DIR
  echo "# $TESTING_DIR">&3
  assert_output --partial '/test/bats'
}

@test "CDOC2 version is found" {
  run echo "$CDOC2_VER"
  echo "# $CDOC2_VER">&3
  # Support also versions with 'SID-' prefix
  assert_output --regexp '^[A-Za-z0-9_-]*[0-9]+\.[0-9]+\.[0-9].*$'
}

@test "preparing: assert BATS_HOME value exists" {
  run ${BATS_HOME}
  echo "# BATS_HOME=$BATS_HOME">&3
  assert_output --partial '/test/bats/target'
}

@test "preparing: assert bats helpers are installed" {
  run "${BATS_HOME}"/bats-core
  assert_output --partial '/test/bats/target/bats-core'
}

@test "preparing: assert TEST_VECTORS package exists" {
  run ${TEST_VECTORS}
  assert_output --partial '/test/testvectors'
}

@test "preparing: assert TEST_VECTORS-V1.2 package exists" {
  run ${TEST_VECTORS_V_1_2}
  assert_output --partial '/test/testvectors-v1.2'
}

@test "preparing: cdoc-cli is available" {
  run $CDOC2_CMD
  assert_output --partial 'cdoc2-cli is a command line interface for cdoc2 library'
}

@test "preparing: assert CDOC2_CONFIG package exists" {
  run ${CDOC2_CONFIG}
  assert_output --partial '/config'
}

@test "preparing: Waiting capsule-server to start" {
  timeout 15s bash -c 'until curl -k --silent --show-error --connect-timeout 1 https://localhost:18443/actuator/health|grep UP; do echo "# Checking ...">&3; sleep 1;done'
}

@test "capsule-server-test1: successfully encrypt CDOC2 container with server capsule and send capsule to server, then use GET server to decrypt" {
  local cdoc_file="ec_simple_to_server.cdoc"
  echo "# Crypt and send capsule to PUT server for file ${cdoc_file}">&3
  run run_alias cdoc-cli \
          create --server="$TESTING_DIR"/config/localhost/localhost_pkcs12.properties \
          -f "$TEST_RESULTS_DIR"/$cdoc_file \
          -p "$TESTING_DIR"/keys/cdoc2client_pub.key "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdoc_file"

  # ensure encrypted container can be decrypted successfully using GET server
  echo "# Capsule sent to PUT server">&3
  echo "# Using GET server to decrypt file ${cdoc_file}">&3
  run run_alias cdoc-cli \
          decrypt --server="$TESTING_DIR"/config/localhost/localhost_pkcs12.properties \
          -f "$TEST_RESULTS_DIR"/$cdoc_file \
           -k "$TESTING_DIR"/keys/cdoc2client_priv.key \
          -o "$TEST_RESULTS_DIR"

  assertSuccessfulExecution
  assert_output --partial "Decrypting $TEST_RESULTS_DIR/$cdoc_file"
  assertSuccessfulDecryption

  rm -f "$TEST_RESULTS_DIR"/$cdoc_file
}

@test "All capsule-server tests were executed." {
  echo "All capsule-server tests were executed."
}

assertSuccessfulExecution() {
  successfulExitCode=0
  assert_success
  assert_equal $status $successfulExitCode
}

assertSuccessfulDecryption() {
  input_filename=$(basename "$FILE_FOR_ENCRYPTION")
  output_filename=$(basename "$DECRYPTED_FILE")
  assert_equal "$output_filename" "$input_filename"
  if [ "$output_filename" == "$input_filename" ]; then
    echo "# File successfully decrypted.">&3
  fi

  rm -f "$DECRYPTED_FILE"
}

assertFailure() {
  failureExitCode=1
  assert_equal $status $failureExitCode
  if [ $status == $failureExitCode ]; then
    echo "# Execution has failed as expected.">&3
  fi
}

removeEncryptedCdoc() {
  rm -f "$CDOC2_CONTAINER"
}

# removes created temporary files within testing
teardown_file() {
  rm -d "$TEST_RESULTS_DIR"
}
