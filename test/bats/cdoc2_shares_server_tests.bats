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

# new directory for re-encrypted containers
REENCRYPTION_DIRECTORY=$TEST_RESULTS_DIR/reencrypt
mkdir -p "$REENCRYPTION_DIRECTORY"

# demo user OK, TESTNUMBER - automatic confirmation
MID_ID_CODE=60001017869
MID_PHONE_NR=+37268000769
SID_ID_CODE=30303039914
PASSWORD_WITH_LABEL="passwordlabel:myPlainTextPassword"
KEY_SHARES_PROPERTIES="$TESTING_DIR/shares-properties/key-shares.properties"
MOBILE_ID_PROPERTIES="$TESTING_DIR/shares-properties/mobile_id-test.properties"
SMART_ID_PROPERTIES="$TESTING_DIR/shares-properties/smart_id-test.properties"


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
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Smart-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$SID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  # ensure encrypted container can be decrypted successfully
  echo "# Encryption key has been shared between servers">&3
  echo "# Requesting key shares from servers to decrypt file ${cdocFile}">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$SID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          -o "$TEST_RESULTS_DIR"

  assertSuccessfulExecution
  assert_output --partial "Decrypting $TEST_RESULTS_DIR/$cdocFile"
  assertSuccessfulDecryption

  rm -f "$TEST_RESULTS_DIR"/"$cdocFile"
}

@test "shares-server-test2: successfully encrypt and decrypt CDOC2 container with Smart-ID EID-Q certs" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Smart-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id="40504040001"\
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id="40504040001" \
          -f "$TEST_RESULTS_DIR"/$cdocFile \
          -o "$TEST_RESULTS_DIR"

  assertSuccessfulExecution
  assert_output --partial "Decrypting $TEST_RESULTS_DIR/$cdocFile "
  assertSuccessfulDecryption

  rm -f "$TEST_RESULTS_DIR"/"$cdocFile "
}

@test "shares-server-test3: fail to decrypt CDOC2 container with wrong ID code" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypting file ${cdocFile} with Smart-ID for ID code ${SID_ID_CODE}">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$SID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile"\
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  echo "# File ${cdocFile} decryption should fail for foreign ID code 47101010033">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id="47101010033" \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          -o "$TEST_RESULTS_DIR"

  assertFailure

  rm -f "$TEST_RESULTS_DIR"/"$cdocFile"
}

@test "shares-server-test4: fail to encrypt CDOC2 container with missing key shares configuration" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypting file ${cdocFile} with Smart-ID for ID code ${SID_ID_CODE}">&3
  run run_alias cdoc-cli \
          create \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$SID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertFailure
}

@test "shares-server-test5: fail to encrypt CDOC2 container with missing Smart-ID configuration" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypting file ${cdocFile} with Smart-ID for ID code ${SID_ID_CODE}">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="wrong file location or missing" \
          --smart-id=$SID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertFailure
}

@test "shares-server-test6: fail to encrypt CDOC2 container with Smart-ID when ID code is invalid" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  invalidIdCode=01987654321
  echo "# Encrypting file ${cdocFile} with Smart-ID for non-existing ID code ${invalidIdCode}">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=${invalidIdCode} \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertFailure
}

@test "shares-server-test7: fail to decrypt CDOC2 container with wrong authentication type" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Smart-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$SID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile"\
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  echo "# Decrypt file ${cdocFile} with Mobile-ID">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$SID_ID_CODE \
          -mid-phone=$MID_PHONE_NR \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          -o "$TEST_RESULTS_DIR"

  assertFailure
}

@test "shares-server-test8: successfully encrypt and decrypt CDOC2 container with Mobile-ID" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Mobile-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  # ensure encrypted container can be decrypted successfully
  echo "# Encryption key has been shared between servers">&3
  echo "# Requesting key shares from servers to decrypt file ${cdocFile}">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -mid-phone=$MID_PHONE_NR \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          -o "$TEST_RESULTS_DIR"

  assertSuccessfulExecution
  assert_output --partial "Decrypting $TEST_RESULTS_DIR/$cdocFile"
  assertSuccessfulDecryption

  rm -f "$TEST_RESULTS_DIR"/"$cdocFile"
}

@test "shares-server-test9: fail to decrypt CDOC2 container with Mobile-ID when phone number is missing" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Mobile-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          -o "$TEST_RESULTS_DIR"

  assertFailure
}

@test "shares-server-test10: fail to decrypt CDOC2 container with Mobile-ID when phone number format is invalid" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Mobile-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  invalidPhoneNr="12212345678"
  echo "# Decrypt file ${cdocFile} with Mobile-ID with invalid phone number format ${invalidPhoneNr}">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -mid-phone=${invalidPhoneNr} \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          -o "$TEST_RESULTS_DIR"

  assertFailure
}

@test "shares-server-test11: fail to encrypt CDOC2 container with Mobile-ID when ID code is invalid" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  invalidIdCode=01987654321
  echo "# Encrypt file ${cdocFile} with Mobile-ID for non-existing ID code ${invalidIdCode}">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=${invalidIdCode} \
          -f "$TEST_RESULTS_DIR"/"$cdocFile"\
          "$FILE_FOR_ENCRYPTION"

  assertFailure
}

@test "shares-server-test12: fail to decrypt CDOC2 container with wrong authentication type" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Mobile-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile"\
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  echo "# Decrypt file ${cdocFile} with Smart-ID">&3
  run run_alias cdoc-cli \
          decrypt -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$MID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile" \
          -o "$TEST_RESULTS_DIR"

  assertFailure
}

@test "shares-server-test13: successfully re-encrypt CDOC2 container from Smart-ID container" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypting file ${cdocFile} with Smart-ID for ID code ${SID_ID_CODE}">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$SID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile"\
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  echo "# Re-encrypting file ${cdocFile} from Smart-ID container">&3
  run run_alias cdoc-cli \
          re -f "$TEST_RESULTS_DIR"/"$cdocFile" --encpassword $PASSWORD_WITH_LABEL \
          -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dsmart-id.properties="$SMART_ID_PROPERTIES" \
          --smart-id=$SID_ID_CODE \
          --output "$REENCRYPTION_DIRECTORY"

  assertSuccessfulExecution

  # ensure re-encrypted container can be decrypted successfully
  echo "# Testing decryption of re-encrypted container ${cdocFile}">&3
  run run_alias cdoc-cli decrypt -f "$REENCRYPTION_DIRECTORY"/"$cdocFile" -pw $PASSWORD_WITH_LABEL --output "$REENCRYPTION_DIRECTORY"
  assertSuccessfulExecution
  assert_output --partial "Decrypting $REENCRYPTION_DIRECTORY/$cdocFile"
  assertSuccessfulDecryption

  rm -f "$REENCRYPTION_DIRECTORY"/README.md
}

@test "shares-server-test14: successfully re-encrypt CDOC2 container from Mobile-ID container" {
  cdocFile="key-shares-$(tr -dC '[:xdigit:]' </dev/urandom | head -c8).cdoc"
  echo "# Encrypt file ${cdocFile} with Mobile-ID">&3
  run run_alias cdoc-cli \
          create -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          --mobile-id=$MID_ID_CODE \
          -f "$TEST_RESULTS_DIR"/"$cdocFile"\
          "$FILE_FOR_ENCRYPTION"

  assertSuccessfulExecution
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdocFile"

  echo "# Re-encrypting file ${cdocFile} from Mobile-ID container">&3
  run run_alias cdoc-cli \
          re -f "$TEST_RESULTS_DIR"/"$cdocFile" --encpassword $PASSWORD_WITH_LABEL \
          -Dkey-shares.properties="$KEY_SHARES_PROPERTIES" \
          -Dmobile-id.properties="$MOBILE_ID_PROPERTIES" \
          -mid=$MID_ID_CODE -mid-phone=$MID_PHONE_NR \
          --output "$REENCRYPTION_DIRECTORY"

  assertSuccessfulExecution

  # ensure re-encrypted container can be decrypted successfully
  echo "# Testing decryption of re-encrypted container ${cdocFile}">&3
  run run_alias cdoc-cli decrypt -f "$REENCRYPTION_DIRECTORY"/"$cdocFile" -pw $PASSWORD_WITH_LABEL --output "$REENCRYPTION_DIRECTORY"
  assertSuccessfulExecution
  assert_output --partial "Decrypting $REENCRYPTION_DIRECTORY/$cdocFile"
  assertSuccessfulDecryption

  rm -f "$REENCRYPTION_DIRECTORY"/README.md
}

@test "All shares-server tests were executed." {
  echo "All shares-server tests were executed."
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
  if [ $status != 0 ]; then
    echo "# Execution has failed as expected.">&3
  fi
}

# removes temporary created directory with files within testing
teardown_file() {
  rm -r "$REENCRYPTION_DIRECTORY"
  rm -r "$TEST_RESULTS_DIR"
}
