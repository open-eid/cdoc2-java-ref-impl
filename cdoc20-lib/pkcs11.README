https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-D3EF9023-7DDC-435D-9186-D2FD05674777
Table 5-3 Supported algorithms


https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-C4ABFACB-B2C9-4E71-A313-79F881488BB9
Table 5-1


cat /etc/opensc/opensc-java.cfg
name=OpenSC
library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
slot=0
attributes(*,CKO_SECRET_KEY,*) = {
CKA_TOKEN = false
}





pkcs15-tool --dump



keytool 
-providerclass sun.security.pkcs11.SunPKCS11 
-providerarg /etc/opensc/opensc-java.cfg 
-keystore NONE
-J-Djava.security.debug=sunpkcs11
-storetype PKCS11 
-list 

jkusman@cn-3615:/etc/opensc$ keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg /etc/opensc/opensc-java.cfg -keystore NONE -storetype PKCS11 -list -J-Djava.security.debug=sunpkcs11
SunPKCS11 loading /etc/opensc/opensc-java.cfg
sunpkcs11: Initializing PKCS#11 library /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
Information for provider SunPKCS11-OpenSC
Library info:
cryptokiVersion: 2.20
manufacturerID: OpenSC Project                  
flags: 0
libraryDescription: OpenSC smartcard framework      
libraryVersion: 0.22
All slots: 0, 1
Slots with tokens: 0, 1
Slot info for slot 0:
slotDescription: Alcor Micro AU9560 00 00                                        
manufacturerID: Generic                         
flags: CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE | CKF_HW_SLOT
hardwareVersion: 0.00
firmwareVersion: 0.00
Token info for token in slot 0:
label: KUSMAN,JANNO,37903130370 (PIN1)
manufacturerID: IDEMIA                          
model: PKCS#15 emulated
serialNumber: AB0584325       
flags: CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED
ulMaxSessionCount: CK_EFFECTIVELY_INFINITE
ulSessionCount: 0
ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE
ulRwSessionCount: 0
ulMaxPinLen: 12
ulMinPinLen: 4
ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION
ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION
ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION
ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION
hardwareVersion: 0.00
firmwareVersion: 0.00
utcTime:
Mechanism CKM_SHA_1:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_SHA224:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_SHA256:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_SHA384:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_SHA512:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_MD5:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_RIPEMD160:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_GOSTR3411:
ulMinKeySize: 0
ulMaxKeySize: 0
flags: 1024 = CKF_DIGEST
Mechanism CKM_ECDSA:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 25176065 = CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_UNCOMPRESS
Mechanism CKM_ECDSA_SHA1:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 10240 = CKF_SIGN | CKF_VERIFY
Mechanism CKM_ECDSA_SHA224:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 10240 = CKF_SIGN | CKF_VERIFY
Mechanism CKM_ECDSA_SHA256:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 10240 = CKF_SIGN | CKF_VERIFY
Mechanism CKM_ECDSA_SHA384:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 10240 = CKF_SIGN | CKF_VERIFY
Mechanism CKM_ECDSA_SHA512:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 10240 = CKF_SIGN | CKF_VERIFY
Mechanism CKM_ECDH1_COFACTOR_DERIVE:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 25690113 = CKF_HW | CKF_DERIVE | CKF_EC_UNCOMPRESS
Mechanism CKM_ECDH1_DERIVE:
ulMinKeySize: 384
ulMaxKeySize: 384
flags: 25690113 = CKF_HW | CKF_DERIVE | CKF_EC_UNCOMPRESS
Enter keystore password:  
sunpkcs11: login succeeded
Keystore type: PKCS11
Keystore provider: SunPKCS11-OpenSC

Your keystore contains 1 entry

Isikutuvastus, PrivateKeyEntry,
Certificate fingerprint (SHA-256): 7A:51:A1:51:1C:81:FC:9F:D3:91:44:50:A9:5D:1F:DF:5A:DD:18:6A:42:F8:76:7E:45:9A:03:2A:EC:6E:12:3C


keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg /etc/opensc/opensc-java.cfg -keystore NONE -storetype PKCS11 -list -J-Djava.security.debug=sunpkcs11 -J-Djava.security.debug=pkcs11keystore

Enter keystore password:  
Token Alias Map:
Isikutuvastus	type=[private key]
label=[Isikutuvastus]
id=0x01
trusted=[false]
matched=[true]
cert=[	subject: SERIALNUMBER=37101010021, GIVENNAME=IGOR, SURNAME=ŽAIKOVSKI, CN="ŽAIKOVSKI,IGOR,37101010021", OU=authentication, O=ESTEID, C=EE
issuer: CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE
serialNum: 119787037079723296282246659404242556136]
pkcs11keystore: P11KeyStore load. Entry count: 1
Keystore type: PKCS11
Keystore provider: SunPKCS11-OpenSC

Your keystore contains 1 entry

Isikutuvastus, PrivateKeyEntry,
Certificate fingerprint (SHA-256): F2:5F:A3:E8:D0:6C:ED:AE:5D:11:77:C1:35:A2:F3:07:42:9B:4D:3A:3C:E9:B6:EC:7F:3A:E3:F9:6A:76:35:01





