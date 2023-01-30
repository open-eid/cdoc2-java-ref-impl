#!/bin/bash
# show commands
set -x #echo ON

LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
LANGUAGE=en_US.UTF-8


# if script should create CDOC documents
RUN_CREATE=true

# if script should decrypt CDOC documents (expect for id-card)
RUN_DECRYPT=false




CDOC_DIR=$(cd .. && pwd) #root of cdoc20_java
TESTVECTORS_DIR=${CDOC_DIR}/test/testvectors
TMP_DIR=/tmp

CDOC_VER=$(cd $CDOC_DIR && mvn help:evaluate -Dexpression=project.version -q -DforceStdout)
#CDOC_VER="0.3.0-SNAPSHOT"

CLI_DIR=${CDOC_DIR}/cdoc20-cli
CLI_KEYS_DIR=${CDOC_DIR}/cdoc20-cli/keys
CLI_JAR=${CDOC_DIR}/cdoc20-cli/target/cdoc20-cli-${CDOC_VER}.jar
CLI_CONF=${CDOC_DIR}/cdoc20-cli/config

SERVER_KEYS_DIR=${CDOC_DIR}/cdoc20-server/keys



CDOC_CREATE_CMD="java -jar ${CLI_JAR} create"
CDOC_DECRYPT_CMD="java -jar ${CLI_JAR} decrypt"
CDOC_LIST_CMD="java -jar ${CLI_JAR} list"

create_simple_ec() {
  local cdoc_file="ec_simple.cdoc"

  if $RUN_CREATE
  then
    echo "Creating ${cdoc_file}"
    $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        -c ${CLI_KEYS_DIR}/cdoc20client-certificate.pem ${CDOC_DIR}/README.md
    echo
  fi

  if $RUN_DECRYPT
  then
    echo "Decrypting ${cdoc_file}"
    $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} -k ${CLI_KEYS_DIR}/cdoc20client.pem -o ${TMP_DIR}
  fi
}

create_ec_server_ria_dev_pkcs12() {
  local cdoc_file="ec_server_ria_dev_pkcs12.cdoc"

  if $RUN_CREATE
  then
    echo "Creating ${cdoc_file}"
    #config file has values relative to cdoc20-cli dir, need to cd to $CLI_DIR
    cd $CLI_DIR && $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        --server=${CLI_CONF}/ria-dev/ria-dev_pkcs12.properties \
        -c ${CLI_KEYS_DIR}/cdoc20client-certificate.pem ${CDOC_DIR}/README.md
    echo
  fi


  if $RUN_DECRYPT
  then
    echo "Decrypting ${cdoc_file}"
      cd $CLI_DIR && $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
          --server=${CLI_CONF}/ria-dev/ria-dev_pkcs12.properties \
          -k ${CLI_KEYS_DIR}/cdoc20client.pem -o ${TMP_DIR}
  fi
}


# encrypt cdoc with certificate downloaded from ldap.sk.ee
# can be decrypted with physical est-eid smart-card only
create_ec_server_ria_dev_id_card() {
  local cdoc_file="ec_server_ria_dev_id_card.cdoc"

  if $RUN_CREATE
  then
    echo "Creating ${cdoc_file}"

    # for decrypting use id-code of est-eid you physically have and know PIN codes
    local isikukood='35803262731'

    #config file has values relative to cdoc20-cli dir, need to cd to $CLI_DIR
    cd $CLI_DIR && $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        --server=${CLI_CONF}/ria-dev/ria-dev.properties \
        -r ${isikukood} ${CDOC_DIR}/README.md
    echo
  fi


  if false
  then
    echo "Decrypting ${cdoc_file}"
      cd $CLI_DIR && $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
          --server=${CLI_CONF}/ria-dev/ria-dev.properties \
          -o ${TMP_DIR}
  fi
}


create_simple_rsa() {
  local cdoc_file="rsa_simple.cdoc"
  if $RUN_CREATE
  then
    echo "Creating ${cdoc_file}"
    $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        -p ${CLI_KEYS_DIR}/rsa_pub.pem ${CDOC_DIR}/README.md
    echo
  fi

  if $RUN_DECRYPT
  then
    echo "Decrypting ${cdoc_file}"
    $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} -k ${CLI_KEYS_DIR}/rsa_priv.pem -o ${TMP_DIR}
  fi
}


create_rsa_server_ria_dev_pkcs12() {
  local cdoc_file="rsa_server_ria_dev_pkcs12.cdoc"

  if $RUN_CREATE
  then
    echo "Creating ${cdoc_file}"
    #config file has values relative to cdoc20-cli dir, need to cd to $CLI_DIR
    cd $CLI_DIR && $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        --server=${CLI_CONF}/ria-dev/ria-dev_pkcs12_rsa.properties \
        -c ${SERVER_KEYS_DIR}/sk-signed-test-certs/cdoc2-rsa-test-sk-cert.pem ${CDOC_DIR}/README.md
    echo
  fi

  if $RUN_DECRYPT
  then
    echo "Decrypting ${cdoc_file}"
    cd $CLI_DIR && $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
          --server=${CLI_CONF}/ria-dev/ria-dev_pkcs12_rsa.properties \
          -p12 ${SERVER_KEYS_DIR}/sk-signed-test-certs/cdoc2-rsa-test-sk.p12:passwd  -o ${TMP_DIR}
  fi
}

create_symmetric() {
  local cdoc_file="symmetric.cdoc"
  if $RUN_CREATE
  then
    echo "Creating ${cdoc_file}"
    $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        --secret "test_label:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=" ${CDOC_DIR}/README.md
  fi
  echo

  if $RUN_DECRYPT
  then
    echo "Decrypting ${cdoc_file}"
    $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
    --secret "test_label:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=" -o ${TMP_DIR}
  fi
}

create_symmetric_longfilename() {
  # over 100 bytes filenames require POSIX tar long filename extension
  local cdoc_file="symmetric_longfilename.cdoc"
  local unicode=$(echo -e "\u2620")
  local long_filename="long_filename_${unicode}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

  if $RUN_CREATE
  then
    touch ${TMP_DIR}/${long_filename}
    echo "Hello from create_symmetric_longfilename()" >> ${TMP_DIR}/${long_filename}
    echo "Creating ${cdoc_file}"
    $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        --secret "test_label:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=" ${TMP_DIR}/${long_filename}
  fi
  echo

  if $RUN_DECRYPT
  then
    echo "Decrypting ${cdoc_file}"
    $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
    --secret "test_label:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=" -o ${TMP_DIR}
  fi
}

create_zipbomb() {
  #over 8GB files require POSIX tar long file extension
  local cdoc_file="zipbomb.cdoc"
  local bomb=$(echo -e "\U0001F4A3")

  # requires 8GB+ of disk space
  if $RUN_CREATE
  then
    #create bomb file with 8GB + 1MB size
    dd if=/dev/zero of=${TMP_DIR}/${bomb} bs=1M count=8193
    echo "Creating ${cdoc_file}"
    $CDOC_CREATE_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
        --secret "test_label:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=" ${TMP_DIR}/${bomb}
    rm ${TMP_DIR}/${bomb}
  fi
  echo

  if $RUN_DECRYPT
  then
    # list succeeds as no files are created
    echo "Listing ${cdoc_file}"
    $CDOC_LIST_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
    --secret "test_label:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE="

    # decrypt should fail with java.lang.IllegalStateException: Gzip compression ratio 20.642857142857142 is over 10.0
#    echo "Decrypting ${cdoc_file}"
#    $CDOC_DECRYPT_CMD --file ${TESTVECTORS_DIR}/${cdoc_file} \
#    --secret "test_label:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=" -o ${TMP_DIR}
  fi

}



create_simple_ec
create_ec_server_ria_dev_pkcs12
create_ec_server_ria_dev_id_card
create_simple_rsa
create_rsa_server_ria_dev_pkcs12
create_symmetric
create_symmetric_longfilename
create_zipbomb



