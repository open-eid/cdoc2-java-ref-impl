#!/usr/bin/env bash

source variables.sh
source aliases.sh

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
mkdir -p $TEST_RESULTS_DIR
FILE_FOR_ENCRYPTION=$CDOC2_DIR/README.md
FILE_FOR_ENCRYPTION2=$CDOC2_DIR/pom.xml
DECRYPTED_FILE=$TEST_RESULTS_DIR/README.md
CDOC2_CONTAINER_NAME="cdoc_test_container.cdoc"
CDOC2_CONTAINER=$TEST_RESULTS_DIR/$CDOC2_CONTAINER_NAME
CLI_KEYS_DIR=$CDOC2_DIR/cdoc2-cli/keys
PW="myPlainTextPassword"
PW_LABEL="passwordlabel"
PASSWORD_WITH_LABEL="$PW_LABEL:$PW"
SECRET="base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE="
SECRET_LABEL="mylabel"
SECRET_WITH_LABEL="$SECRET_LABEL:$SECRET"


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
  assert_output --regexp '^[0-9]+\.[0-9]+\.[0-9].*$'
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

@test "test1: successfully encrypt CDOC2 container with EC" {
  local cdoc_file="ec_simple.cdoc"
  run run_alias cdoc-cli create -f $TEST_RESULTS_DIR/$cdoc_file \
          -c $CLI_KEYS_DIR/cdoc2client-certificate.pem $FILE_FOR_ENCRYPTION

  assertSuccessfulExitCode
  assert_output --partial "Created $TEST_RESULTS_DIR/$cdoc_file"

  # ensure encrypted container can be decrypted successfully
  run run_alias cdoc-cli decrypt -f $TEST_RESULTS_DIR/$cdoc_file -k $CLI_KEYS_DIR/cdoc2client.pem -o $TEST_RESULTS_DIR
  assertSuccessfulDecryption

  rm -f $TEST_RESULTS_DIR/$cdoc_file
}

@test "test2: assert EC decryption is compatible with earlier encrypted CDOC2" {
  local cdoc_file="ec_simple_old_version_DO_NOT_DELETE.cdoc"

  echo "# Decrypting ${cdoc_file}">&3
  run run_alias cdoc-cli decrypt -f ${TEST_VECTORS}/${cdoc_file} -k $CLI_KEYS_DIR/cdoc2client.pem --output $TEST_RESULTS_DIR

  assertSuccessfulExitCode
  assert_output --partial "Decrypting ${TEST_VECTORS}/${cdoc_file}"
  assertSuccessfulDecryption
}

@test "test3: successfully encrypt CDOC2 container with RSA" {
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

@test "test4: successfully encrypt CDOC2 container with password" {
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode
  assert_output --partial "Created $CDOC2_CONTAINER"
}

@test "test5: successfully decrypt CDOC2 container from test1 with password" {
  run run_alias cdoc-cli decrypt -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL --output $TEST_RESULTS_DIR
  assertSuccessfulExitCode
  assert_output --partial "Decrypting $CDOC2_CONTAINER"
  assertSuccessfulDecryption
}

@test "test5a: successfully decrypt CDOC2 container from test1 with password and without label" {
  run run_alias cdoc-cli decrypt -f $CDOC2_CONTAINER -pw ":$PW" --output $TEST_RESULTS_DIR
  assertSuccessfulExitCode
  assert_output --partial "Decrypting $CDOC2_CONTAINER"
  assertSuccessfulDecryption

  removeEncryptedCdoc
}


@test "test6: assert password decryption is compatible with earlier encrypted CDOC2" {
  local existing_test_vector="password_old_version_DO_NOT_DELETE.cdoc"

  echo "# Decrypting ${existing_test_vector}">&3
  run run_alias cdoc-cli decrypt -f ${TEST_VECTORS}/${existing_test_vector} -pw $PASSWORD_WITH_LABEL --output $TEST_RESULTS_DIR

  assertSuccessfulExitCode
  assert_output --partial "Decrypting ${TEST_VECTORS}/${existing_test_vector}"
  assertSuccessfulDecryption
}

@test "test7: assert decryption with symmetric key is compatible with earlier encrypted CDOC2" {
  local existing_test_vector="symmetric_old_version_DO_NOT_DELETE.cdoc"

  echo "# Decrypting ${existing_test_vector}">&3
  run run_alias cdoc-cli decrypt -f ${TEST_VECTORS}/${existing_test_vector} --secret $SECRET_WITH_LABEL --output $TEST_RESULTS_DIR

  assertSuccessfulExitCode
  assert_output --partial "Decrypting ${TEST_VECTORS}/${existing_test_vector}"
  assertSuccessfulDecryption
}

@test "test8: successfully encrypt CDOC2 container with few files" {
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL $FILE_FOR_ENCRYPTION $FILE_FOR_ENCRYPTION2
  assertSuccessfulExitCode

  removeEncryptedCdoc
}

@test "test9: fail to encrypt CDOC2 container with password if it's validation has failed" {
  password="passwordlabel:short";
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER -pw $password $FILE_FOR_ENCRYPTION
  assertFailure
}

@test "test10: fail to decrypt CDOC2 container with wrong decryption key type" {
  # encrypt with secret key
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER --secret $SECRET_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode

  # try to decrypt with password
  run run_alias cdoc-cli decrypt -f $CDOC2_CONTAINER -pw $PASSWORD_WITH_LABEL --output $TEST_RESULTS_DIR
  assertFailure

  removeEncryptedCdoc
}

@test "test11: successfully encrypt CDOC with two keys and decrypt with one of them" {
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

@test "test12: successfully re-encrypt CDOC2 container" {
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

@test "test13: fail re-encryption within the same directory" {
  run run_alias cdoc-cli create -f $CDOC2_CONTAINER --secret $SECRET_WITH_LABEL $FILE_FOR_ENCRYPTION
  assertSuccessfulExitCode

  run run_alias cdoc-cli re -f $CDOC2_CONTAINER --encpassword $PASSWORD_WITH_LABEL --secret $SECRET_WITH_LABEL --output $TEST_RESULTS_DIR
  assertFailure

  removeEncryptedCdoc
}

# bats test_tags=expect
@test "test14: interactively encrypt/decrypt with password" {
  #echo "# HAS_EXPECT $HAS_EXPECT" >&3
  if (! $HAS_EXPECT) ; then
    #echo "Skipping ..." >&3
    skip "'expect' not installed"
  fi

  # bats doesn't directly support interactive scripts, run expect script
  tmp_expect_script=$(mktemp --tmpdir=$TEST_RESULTS_DIR)
  cat >"$tmp_expect_script" <<EOF
#!/usr/bin/expect -d
set timeout 3
spawn $CDOC2_CMD encrypt -pw -f $CDOC2_CONTAINER $FILE_FOR_ENCRYPTION -Dee.cyber.cdoc2.overwrite=true
expect {
  "Password is missing. Please enter:" {
    send "$PW\r"
  } timeout {
    exit -1
  }
}
expect {
  "Re-enter password:" {
    send "$PW\r"
  } timeout {
    exit -1
  }
}
expect {
  "Please enter label:" {
    send "$PW_LABEL\r"
  } timeout {
    exit -1
  }
}
expect eof

#interact

#return exit code from cdoc-cli
catch wait result
exit [lindex \$result 3]
EOF

  #echo "# expect $tmp_expect_script" >&3
  chmod +x $tmp_expect_script
  eval "run $tmp_expect_script"

  assert_success

  # bats doesn't directly support interactive scripts, run expect
  tmp_expect_decrypt_script=$(mktemp --tmpdir=$TEST_RESULTS_DIR)
  cat >"$tmp_expect_decrypt_script" <<EOF
#!/usr/bin/expect -d
set timeout 3
spawn $CDOC2_CMD decrypt -pw -f $CDOC2_CONTAINER --output $TEST_RESULTS_DIR -Dee.cyber.cdoc2.overwrite=true
expect {
  "Password is missing. Please enter:" {
    send "$PW\r"
  } timeout {
    exit -1
  }
}
expect eof

#return exit code from cdoc-cli
catch wait result
exit [lindex \$result 3]
EOF
  #echo "# expect $tmp_expect_decrypt_script" >&3
  chmod +x $tmp_expect_decrypt_script
  run $tmp_expect_decrypt_script

  assertSuccessfulExitCode
  assertSuccessfulDecryption

  removeEncryptedCdoc

  rm -rf $tmp_expect_script
  rm -rf $tmp_expect_decrypt_script
}

@test "test15: assert earlier encrypted CDOC2 with Symmetric key displays only pure key label" {
  local cdoc_file="symmetric_old_version_DO_NOT_DELETE.cdoc"

  echo "# Requesting info for ${cdoc_file}">&3
  run run_alias cdoc-cli info -f ${TEST_VECTORS}/${cdoc_file}

  assertSuccessfulExitCode
  local expected_output_info="SymmetricKey: LABEL:$SECRET_LABEL "
  echo "# $expected_output_info">&3
  assert_equal "$output" "$expected_output_info"
}

@test "test16: assert earlier encrypted CDOC2 with password displays only pure key label" {
  local cdoc_file="password_old_version_DO_NOT_DELETE.cdoc"

  echo "# Requesting info for ${cdoc_file}">&3
  run run_alias cdoc-cli info -f ${TEST_VECTORS}/${cdoc_file}

  assertSuccessfulExitCode
  local expected_output_info="Password: LABEL:$PW_LABEL "
  echo "# $expected_output_info">&3
  assert_equal "$output" "$expected_output_info"
}

@test "test17: assert earlier encrypted CDOC2 with EC key displays only pure key label" {
  local cdoc_file="ec_simple_old_version_DO_NOT_DELETE.cdoc"

  echo "# Requesting info for ${cdoc_file}">&3
  run run_alias cdoc-cli info -f ${TEST_VECTORS}/${cdoc_file}

  assertSuccessfulExitCode
  local expected_output_info="EC PublicKey: LABEL:cdoc20-client "
  echo "# $expected_output_info">&3
  assert_equal "$output" "$expected_output_info"
}

@test "test18: assert newly encrypted CDOC2 with EC key displays formatted key label" {
  local cdoc_file="ec_simple_with_formatted_key_label.cdoc"
  run run_alias cdoc-cli create -f $TEST_RESULTS_DIR/$cdoc_file \
          -c $CLI_KEYS_DIR/cdoc2client-certificate.pem $FILE_FOR_ENCRYPTION

  echo "# Requesting info for ${cdoc_file}">&3
  run run_alias cdoc-cli info -f ${TEST_RESULTS_DIR}/${cdoc_file}

  assertSuccessfulExitCode
  local expected_output_info="EC PublicKey: CERT_SHA1:5d5d9c00eeb79d89e3a54e791a6256f892ad9411, V:1, CN:cdoc20-client, FILE:cdoc2client-certificate.pem, TYPE:cert "
  echo "# $expected_output_info">&3
  assert_output --partial "EC PublicKey:"
  assert_output --partial "CERT_SHA1:5d5d9c00eeb79d89e3a54e791a6256f892ad9411"
  assert_output --partial "V:1"
  assert_output --partial "CN:cdoc20-client"
  assert_output --partial "FILE:cdoc2client-certificate.pem"
  assert_output --partial "TYPE:cert"

  rm -f $TEST_RESULTS_DIR/$cdoc_file
}

@test "test18a: assert earlier encrypted CDOC2 with EC key displays formatted key label and successfully decrypted" {
  local existing_test_vector="ec_simple_with_formatted_key_label.cdoc"

  echo "# Requesting info for ${existing_test_vector}">&3
  run run_alias cdoc-cli info -f ${TEST_VECTORS_V_1_2}/${existing_test_vector}

  assertSuccessfulExitCode
  local expected_output_info="EC PublicKey: CERT_SHA1:5d5d9c00eeb79d89e3a54e791a6256f892ad9411, V:1, CN:cdoc20-client, FILE:cdoc2client-certificate.pem, TYPE:cert "
  echo "# $expected_output_info">&3
  assert_output --partial "EC PublicKey:"
  assert_output --partial "CERT_SHA1:5d5d9c00eeb79d89e3a54e791a6256f892ad9411"
  assert_output --partial "V:1"
  assert_output --partial "CN:cdoc20-client"
  assert_output --partial "FILE:cdoc2client-certificate.pem"
  assert_output --partial "TYPE:cert"

  # ensure encrypted container can be decrypted successfully
  run run_alias cdoc-cli decrypt -f $TEST_VECTORS_V_1_2/$existing_test_vector -k $CLI_KEYS_DIR/cdoc2client.pem -o $TEST_RESULTS_DIR
  assertSuccessfulDecryption

  rm -f $TEST_RESULTS_DIR/$existing_test_vector
}

@test "test19: assert newly encrypted CDOC2 with RSA key displays formatted key label" {
  local cdoc_file="rsa_simple_with_formatted_key_label.cdoc"
  run run_alias cdoc-cli create -f $TEST_RESULTS_DIR/$cdoc_file \
          -p $CLI_KEYS_DIR/rsa_pub.pem $FILE_FOR_ENCRYPTION

  echo "# Requesting info for ${cdoc_file}">&3
  run run_alias cdoc-cli info -f ${TEST_RESULTS_DIR}/${cdoc_file}

  assertSuccessfulExitCode
  local expected_output_info="RSA PublicKey: V:1, FILE:rsa_pub.pem, TYPE:pub_key "
  echo "# $expected_output_info">&3
  assert_output --partial "RSA PublicKey:"
  assert_output --partial "V:1"
  assert_output --partial "FILE:rsa_pub.pem"
  assert_output --partial "TYPE:pub_key"

  rm -f $TEST_RESULTS_DIR/$cdoc_file
}

@test "test19a: assert earlier encrypted CDOC2 with RSA key displays formatted key label and successfully decrypted" {
  local existing_test_vector="rsa_simple_with_formatted_key_label.cdoc"

  echo "# Requesting info for ${existing_test_vector}">&3
  run run_alias cdoc-cli info -f ${TEST_VECTORS_V_1_2}/${existing_test_vector}

  assertSuccessfulExitCode
  local expected_output_info="RSA PublicKey: V:1, FILE:rsa_pub.pem, TYPE:pub_key "
  echo "# $expected_output_info">&3
  assert_output --partial "RSA PublicKey:"
  assert_output --partial "V:1"
  assert_output --partial "FILE:rsa_pub.pem"
  assert_output --partial "TYPE:pub_key"

  # ensure encrypted container can be decrypted successfully
  run run_alias cdoc-cli decrypt -f $TEST_VECTORS_V_1_2/$existing_test_vector -k $CLI_KEYS_DIR/rsa_priv.pem -o $TEST_RESULTS_DIR
  assertSuccessfulDecryption

  rm -f $TEST_RESULTS_DIR/$existing_test_vector
}

@test "test20: assert newly encrypted CDOC2 with Symmetric key displays formatted key label" {
  local cdoc_file="symmetric_with_formatted_key_label.cdoc"
  run run_alias cdoc-cli create -f $TEST_RESULTS_DIR/$cdoc_file --secret $SECRET_WITH_LABEL $FILE_FOR_ENCRYPTION

  echo "# Requesting info for ${cdoc_file}">&3
  run run_alias cdoc-cli info -f ${TEST_RESULTS_DIR}/${cdoc_file}

  assertSuccessfulExitCode
  local expected_output_info="SymmetricKey: V:1, LABEL:$SECRET_LABEL, TYPE:secret "
  echo "# $expected_output_info">&3
  assert_output --partial "SymmetricKey:"
  assert_output --partial "V:1"
  assert_output --partial "LABEL:$SECRET_LABEL"
  assert_output --partial "TYPE:secret"

  rm -f $TEST_RESULTS_DIR/$cdoc_file
}

@test "test20a: assert earlier encrypted CDOC2 with Symmetric key displays formatted key label and successfully decrypted" {
  local existing_test_vector="symmetric_with_formatted_key_label.cdoc"

  echo "# Requesting info for ${existing_test_vector}">&3
  run run_alias cdoc-cli info -f ${TEST_VECTORS_V_1_2}/${existing_test_vector}

  assertSuccessfulExitCode
  local expected_output_info="SymmetricKey: V:1, LABEL:$SECRET_LABEL, FILE:$existing_test_vector, TYPE:secret "
  echo "# $expected_output_info">&3
  assert_output --partial "SymmetricKey:"
  assert_output --partial "V:1"
  assert_output --partial "LABEL:$SECRET_LABEL"
  assert_output --partial "TYPE:secret"

  # ensure encrypted container can be decrypted successfully
  echo "# Decrypting ${existing_test_vector}">&3
  run run_alias cdoc-cli decrypt -f ${TEST_VECTORS_V_1_2}/${existing_test_vector} --secret $SECRET_WITH_LABEL --output $TEST_RESULTS_DIR

  assertSuccessfulExitCode
  assert_output --partial "Decrypting ${TEST_VECTORS_V_1_2}/${existing_test_vector}"
  assertSuccessfulDecryption

  rm -f $TEST_RESULTS_DIR/$existing_test_vector
}

@test "test21: assert newly encrypted CDOC2 with password displays formatted key label" {
  local cdoc_file="password_with_formatted_key_label.cdoc"
  run run_alias cdoc-cli create -f $TEST_RESULTS_DIR/$cdoc_file -pw $PASSWORD_WITH_LABEL $FILE_FOR_ENCRYPTION

  echo "# Requesting info for ${cdoc_file}">&3
  run run_alias cdoc-cli info -f ${TEST_RESULTS_DIR}/${cdoc_file}

  assertSuccessfulExitCode
  local expected_output_info="Password: V:1, LABEL:${PW_LABEL}, TYPE:pw "
  echo "# $expected_output_info">&3
  assert_output --partial "Password:"
  assert_output --partial "V:1"
  assert_output --partial "LABEL:${PW_LABEL}"
  assert_output --partial "TYPE:pw"

  rm -f $TEST_RESULTS_DIR/$cdoc_file
}

@test "test21a: assert earlier encrypted CDOC2 with password displays formatted key label and successfully decrypted" {
  local existing_test_vector="password_with_formatted_key_label.cdoc"

  echo "# Requesting info for ${existing_test_vector}">&3
  run run_alias cdoc-cli info -f ${TEST_VECTORS_V_1_2}/${existing_test_vector}

  assertSuccessfulExitCode
  local expected_output_info="Password: V:1, LABEL:${PW_LABEL}, TYPE:pw "
  echo "# $expected_output_info">&3
  assert_output --partial "Password:"
  assert_output --partial "V:1"
  assert_output --partial "LABEL:${PW_LABEL}"
  assert_output --partial "TYPE:pw"

  # ensure encrypted container can be decrypted successfully
  echo "# Decrypting ${existing_test_vector}">&3
  run run_alias cdoc-cli decrypt -f ${TEST_VECTORS_V_1_2}/${existing_test_vector} -pw $PASSWORD_WITH_LABEL --output $TEST_RESULTS_DIR

  assertSuccessfulExitCode
  assert_output --partial "Decrypting ${TEST_VECTORS_V_1_2}/${existing_test_vector}"
  assertSuccessfulDecryption

  rm -f $TEST_RESULTS_DIR/$existing_test_vector
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
