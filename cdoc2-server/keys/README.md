
### Generate server key store
```
keytool -genkeypair -alias cdoc2-server -keyalg ec -groupname secp384r1 -sigalg SHA512withECDSA -keystore cdoc2server.p12 -storepass passwd -ext san=ip:127.0.0.1,dns:localhost
keytool -exportcert -keystore cdoc2server.p12 -alias cdoc2-server -storepass passwd -rfc -file server-certificate.pem
openssl x509 -in server-certificate.pem -text
```

Add the server certificate to the client's trust store:

```
keytool -import -trustcacerts -file server-certificate.pem -alias cdoc2-server -keypass password -storepass passwd -keystore clienttruststore.jks
```

Gen temp client key store and add it to server trust store(to be replaced with cert from id-kaart)
```
keytool -genkeypair -alias cdoc2-client -keyalg ec -groupname secp384r1 -sigalg SHA512withECDSA -keystore cdoc2client.p12 -storepass passwd -ext san=ip:127.0.0.1,dns:localhost
keytool -exportcert -keystore cdoc2client.p12 -alias cdoc2-client -storepass passwd -rfc -file client-certificate.pem
keytool -import -trustcacerts -file client-certificate.pem -alias cdoc2-client -storepass passwd -keystore servertruststore.jks
```

Add TEST of ESTEID-SK 2015 (test id-kaart issuer)
and esteid2018 (id-kaart issuer) and server trust store so that id-kaart certificates are trusted by the server
```
keytool -import -trustcacerts -file ca_certs/TEST_of_ESTEID-SK_2015.pem.crt -alias TEST_of_ESTEID-SK_2015 -storepass passwd -keystore servertruststore.jks
keytool -import -trustcacerts -file ca_certs/esteid2018.pem.crt -alias esteid2018 -storepass passwd -keystore servertruststore.jks
```
