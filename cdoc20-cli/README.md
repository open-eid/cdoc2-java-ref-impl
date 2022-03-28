##Building & Running

###Building
Run cdoc20 parent directory
```
mvn package
```

###Running
Run from cdoc20-cli directory

To create:
- Output file `/tmp/mydoc.cdoc`
- with private EC key `keys/alice.pem`
- to recipient `keys/bob_pub.pem`
- to encrypt file 'README.md'

Run:
```
cdoc20-cli/target/appassembler/bin/cdoc create --file /tmp/mydoc.cdoc --key keys/alice.pem --pubkey keys/bob_pub.pem README.md
```


##Generating EC keys

Generate an EC private key, of size 384, and output it to a file named key.pem:
```
openssl ecparam -name secp384r1 -genkey -noout -out key.pem
```

Extract the public key from the key pair, which can be used in a certificate:
```
openssl ec -in key.pem -pubout -out public.pem
```

Print key info
```
openssl ec -in key.pem -text -noout
```
```
read EC key
Private-Key: (384 bit)
priv:
    0b:b0:1e:fc:ee:51:c2:c3:48:e1:11:ac:2e:8f:3b:
    b5:7c:3d:58:5b:0e:cc:d7:1f:78:6f:00:df:83:43:
    cf:e0:d4:05:fb:38:4e:43:e1:fe:31:27:a4:4e:97:
    cf:70:3f
pub:
    04:ab:3c:e5:c3:1c:c8:8a:01:6d:05:19:9a:5f:8d:
    d5:d6:d8:d0:fe:e7:b9:c2:c7:6a:00:21:e0:3c:5a:
    32:78:d2:f4:1a:82:a2:3b:5b:75:11:e5:9d:98:11:
    de:4c:ff:aa:d4:fb:9c:b6:b8:eb:a5:c8:d3:35:fb:
    0e:6d:df:f3:4f:50:47:64:ae:07:88:3e:ba:54:ba:
    9e:02:54:65:5c:06:50:97:0b:e3:98:ee:91:fc:9d:
    b5:40:95:3e:51:2d:bc
ASN1 OID: secp384r1
NIST CURVE: P-384
```

