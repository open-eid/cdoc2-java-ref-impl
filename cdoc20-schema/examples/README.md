This directory contains example binaries in flatbuffer format. To view bin files in human-readable format, 
use flatc compiler:

`bin/flatc --json --strict-json --raw-binary ../src/main/fbs/header.fbs -- Header.bin`
will create `Header.json`:
```
{"recipients": [{"details_type": "recipients_ECCPublicKey", "details": {"curve": "secp384r1", "recipient_public_key": [114, 101, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254], "sender_public_key": [115, 101, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]}, "encrypted_fmk": [102, 109, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255], "fmk_encryption_method": "XOR"}], "payload_encryption_method": "CHACHA20POLY1305"}
```
