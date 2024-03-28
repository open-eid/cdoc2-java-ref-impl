This directory contains pre-generate EC keys and downloaded id-card certificates.

## Convert X509 Certificate DER to PEM
.der and .cer are the same binary format. 
```
openssl x509 -inform der -in 37101010021.der -out 37101010021.pem
```

## Print X509 cert info
```
openssl x509 -in 37101010021.pem -text
```

## Generating EC keys

Generate an EC private key, of size 384, and output it to a file named key.pem:
```
openssl ecparam -name secp384r1 -genkey -noout -out key.pem
```

```
cat key.pem
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
-----END EC PRIVATE KEY-----
```

Extract the public key from the key pair, which can be used in a certificate:
```
openssl ec -in key.pem -pubout -out public.pem
```

```
cat public.pem
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhEZdaw/m5tmqIrhonGPKG0ZHLPo7fJLO
IwtYw/3/xEPCnRWKyfisJzOkfKyF6g51JyyRYhdzsw6bvE1I1Tr3V4M0C/p+u0Ii
3cnq0xOn+boyF6FzZGQfDtpF/97wA7gw
-----END PUBLIC KEY-----
```


### Print key info
```
openssl ec -in key.pem -text -noout
```
```
read EC key
Private-Key: (384 bit)
priv:
    61:d5:40:13:f3:7d:8d:87:66:57:bd:d7:39:25:b3:
    6f:dc:17:04:65:26:24:f7:47:ac:52:44:8f:16:68:
    36:5c:4b:a8:03:b6:af:4b:f9:1d:e0:7b:47:19:16:
    d1:45:b6
pub:
    04:84:46:5d:6b:0f:e6:e6:d9:aa:22:b8:68:9c:63:
    ca:1b:46:47:2c:fa:3b:7c:92:ce:23:0b:58:c3:fd:
    ff:c4:43:c2:9d:15:8a:c9:f8:ac:27:33:a4:7c:ac:
    85:ea:0e:75:27:2c:91:62:17:73:b3:0e:9b:bc:4d:
    48:d5:3a:f7:57:83:34:0b:fa:7e:bb:42:22:dd:c9:
    ea:d3:13:a7:f9:ba:32:17:a1:73:64:64:1f:0e:da:
    45:ff:de:f0:03:b8:30
ASN1 OID: secp384r1
NIST CURVE: P-384
```


PEM files can also be decoded with online ASN.1 Decoder - for example https://holtstrom.com/michael/tools/asn1decoder.php
decodes `key.pem` as following:
```
SEQUENCE {
   INTEGER 0x01 (1 decimal)
   OCTETSTRING 61d54013f37d8d876657bdd73925b36fdc1704652624f747ac52448f1668365c4ba803b6af4bf91de07b471916d145b6
   [0] {
      OBJECTIDENTIFIER 1.3.132.0.34 (P-384)
   }
   [1] {
      BITSTRING 0x0484465d6b0fe6e6d9aa22b8689c63ca1b46472cfa3b7c92ce230b58c3fdffc443c29d158ac9f8ac2733a47cac85ea0e75272c91621773b30e9bbc4d48d53af75783340bfa7ebb4222ddc9ead313a7f9ba3217a17364641f0eda45ffdef003b830 : 0 unused bit(s)
   }
}
```
and `public.pem`:
```
SEQUENCE {
   SEQUENCE {
      OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
      OBJECTIDENTIFIER 1.3.132.0.34 (P-384)
   }
   BITSTRING 0x0484465d6b0fe6e6d9aa22b8689c63ca1b46472cfa3b7c92ce230b58c3fdffc443c29d158ac9f8ac2733a47cac85ea0e75272c91621773b30e9bbc4d48d53af75783340bfa7ebb4222ddc9ead313a7f9ba3217a17364641f0eda45ffdef003b830 : 0 unused bit(s)
}
```

