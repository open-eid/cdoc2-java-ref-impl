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

TEST_RESULTS_DIR=$TESTING_DIR/target/results


mkdir -p "$TEST_RESULTS_DIR"
# demo user OK, TESTNUMBER - automatic confirmation
ID_CODE=30303039914
KEY_SHARES_PROPERTIES="$TESTING_DIR/shares-properties/key-shares.properties"
SMART_ID_PROPERTIES="$TESTING_DIR/shares-properties/smart_id-test.properties"
CDOC_FILE="smartid.cdoc"

#bats run doesn't support alias
#https://github.com/bats-core/bats-core/issues/259
run_alias() {
	shopt -s expand_aliases
	source "aliases_server.sh"
	eval "$*"
}

@test "Starting..." {
  echo "# Preparing shares-server tests...">&3
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

@test "preparing: cdoc-cli is available" {
  run $CDOC2_CMD
  assert_output --partial 'cdoc2-cli is a command line interface for cdoc2 library'
}

@test "preparing: assert CDOC2_CONFIG package exists" {
  run ${CDOC2_CONFIG}
  assert_output --partial '/config'
}

@test "preparing: Waiting shares-server to start" {
  timeout 15s bash -c 'until curl -k --silent --show-error --connect-timeout 1 https://localhost:18443/actuator/health|grep UP; do echo "# Checking ...">&3; sleep 1;done'
}

@test "shares-server-test1: successfully encrypt and decrypt CDOC2 container with Smart-ID" {
  echo "# Encrypt file ${CDOC_FILE} with Smart-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$ID_CODE \
          -f "$TEST_RESULTS_DIR"/$CDOC_FILE \
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$CDOC_FILE"

  # ensure encrypted container can be decrypted successfully
  echo "# Encryption key has been shared between servers">&3
  echo "# Requesting key shares from servers to decrypt file ${CDOC_FILE}">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$ID_CODE \
          -f "$TEST_RESULTS_DIR"/$CDOC_FILE \
          -o "$TEST_RESULTS_DIR"

  assertSuccessfulExecution
  assert_output --partial "Decrypting $TEST_RESULTS_DIR/$CDOC_FILE"
  assertSuccessfulDecryption

  rm -f "$TEST_RESULTS_DIR"/$CDOC_FILE
}

@test "shares-server-test2: fail to decrypt CDOC2 container with wrong ID code" {
  echo "# Encrypting file ${CDOC_FILE} with Smart-ID for ID code ${ID_CODE}">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$ID_CODE \
          -f "$TEST_RESULTS_DIR"/$CDOC_FILE\
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$CDOC_FILE"

  echo "# File ${CDOC_FILE} decryption should fail for foreign ID code 47101010033">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id="47101010033" \
          -f "$TEST_RESULTS_DIR"/$CDOC_FILE \
          -o "$TEST_RESULTS_DIR"

  assertFailure

  rm -f "$TEST_RESULTS_DIR"/$CDOC_FILE
}

@test "shares-server-test3: fail to encrypt CDOC2 container with missing key shares configuration" {
  echo "# Encrypting file ${CDOC_FILE} with Smart-ID for ID code ${ID_CODE}">&3
  run run_alias cdoc-cli \
          create \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$ID_CODE \
          -f "$TEST_RESULTS_DIR"/$CDOC_FILE \
          "$FILE_FOR_ENCRYPTION"

  assertFailure
}

@test "shares-server-test4: fail to encrypt CDOC2 container with missing Smart-ID configuration" {
  echo "# Encrypting file ${CDOC_FILE} with Smart-ID for ID code ${ID_CODE}">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          --smart-id=$ID_CODE \
          -f "$TEST_RESULTS_DIR"/$CDOC_FILE \
          "$FILE_FOR_ENCRYPTION"

  assertFailure
}

@test "All shares-server tests were executed." {
  echo "All shares-server tests were executed."
}

assertSuccessfulExecution() {
  successfulExitCode=0
  if [ "$successfulExitCode" != 0 ]; then
    rm -f "$TEST_RESULTS_DIR/$CDOC_FILE"
  fi

  assert_success
  assert_equal $status $successfulExitCode
}

assertSuccessfulDecryption() {
  input_filename=$(basename "$FILE_FOR_ENCRYPTION")
  output_filename=$(basename "$DECRYPTED_FILE")

  if [ "$status" != 0 ]; then
    rm -f "$TEST_RESULTS_DIR/$CDOC_FILE"
  fi

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
