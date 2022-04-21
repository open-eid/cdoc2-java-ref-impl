package ee.cyber.cdoc20.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class Pkcs11Test {
    private static final Logger log = LoggerFactory.getLogger(Pkcs11Test.class);

    private static final String SUN_PKCS11_KEYSTORE_TYPE = "PKCS11";
    private static final String SUN_PKCS11_PROVIDERNAME = "SunPKCS11";
    private static final String SUN_PKCS11_CLASSNAME = "sun.security.pkcs11.SunPKCS11";

    private static Provider sunPkcs11Provider;

    private static final String pkcs11Config =
                    "name=OpenSC\n" +
                    "library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so\n" +
                    "slot=0";

    private static final String BOB_PUB_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEeWGnKaeR+GgQCMZA7XQV3MPwRcjDRELu\n" +
            "AS6pxL9XFFR0Tp4cN4QFutxdx9jyPd2cwfwU+vgvoDi7d15Ak/x9wvV9WZLQneZU\n" +
            "tgZgvMzeFHIsK02+vILeMpSlAneYN9Cm\n" +
            "-----END PUBLIC KEY-----";


    private static Provider getProvider(String configString) throws Exception{
        //https://ec.europa.eu/digital-building-blocks/code/projects/ESIG/repos/dss/browse/dss-token/src/main/java/eu/europa/esig/dss/token/Pkcs11SignatureToken.java?at=2b20a5d720429b25dbebd275f0285e6b2aa52c0c
        Provider provider = Security.getProvider(SUN_PKCS11_PROVIDERNAME);
        Method configureMethod = provider.getClass().getMethod("configure", String.class);
        return (Provider) configureMethod.invoke(provider, configString);
    }

    @BeforeAll
    static void initPkcs11() throws Exception {
        String configName = "/etc/opensc/opensc-java.cfg";
        sunPkcs11Provider = Security.getProvider("SunPKCS11");
        sunPkcs11Provider = sunPkcs11Provider.configure(configName);



        log.debug("Provider name {}", sunPkcs11Provider.getName());
        log.debug("Provider info {}", sunPkcs11Provider.getInfo());

        log.debug("Provider properties: {}", sunPkcs11Provider.stringPropertyNames());

        //sunPkcs11Provider.getServices().forEach(s -> log.debug("{} {}",s.getAlgorithm(), s.getType()));

        Security.addProvider(sunPkcs11Provider);

        Provider sun = Security.getProvider("SunPKCS11-OpenSC");
        log.debug("SunPKCS11-OpenSC provider isConfigured={}", sun.isConfigured());
    }

    KeyPair loadPkcs11KeyPair() throws GeneralSecurityException, IOException{
        String key1 = "Isikutuvastus";
        String pin1 = "3471";
        KeyStore ks = KeyStore.getInstance("PKCS11", sunPkcs11Provider.getName());
        ks.load(null, pin1.toCharArray());

        ks.aliases().asIterator().forEachRemaining(alias -> {
            try {
                log.debug("{} key={} cert={}", alias, ks.isKeyEntry(alias), ks.isCertificateEntry(alias));
            } catch (KeyStoreException e) {
                log.error("KeyStoreException", e);
            }
        });

        //can't cast to ECPrivateKey
        PrivateKey key = (PrivateKey)ks.getKey(key1, pin1.toCharArray());
        X509Certificate cert = (X509Certificate)ks.getCertificate(key1);

        log.debug("key: {} {}", key.getAlgorithm(), key);
        log.debug("cert: {} ", cert.getSubjectX500Principal().getName());


        KeyPair pkcs11KeyPair = new KeyPair(cert.getPublicKey(), key);

        return pkcs11KeyPair;

    }


//    @Test
//    void testDeriveKeyEncryptionKey() throws GeneralSecurityException, IOException {
//
//        ECPublicKey otherPublicKey = ECKeys.loadECPublicKey(BOB_PUB_KEY);
//
//
//        KeyPair pkcs11KeyPair = loadKeyPair();
//
//
//
//
////        KeyAgreement ka = KeyAgreement.getInstance("ECDH", sunPkcs11Provider);
////        ka.init(key);
////        ka.doPhase(otherPublicKey, true);
////        byte[] ecdhSharedSecret = ka.generateSecret();
////        assertEquals(ECKeys.SECP_384_R_1_LEN_BYTES, ecdhSharedSecret.length);
//
//        byte[] fmk = Crypto.generateFileMasterKey();
//        //SecretKey secretKey = Crypto.deriveContentEncryptionKey(fmk);
//
//
//        byte[] kek = Crypto.deriveKeyEncryptionKey(pkcs11KeyPair, otherPublicKey, fmk.length);
//        byte[] encryptedFmk = Crypto.xor(fmk, kek);
//        byte[] decrypted = Crypto.xor(encryptedFmk, kek);
//
//        log.debug("FMK:       {}", HexFormat.of().formatHex(fmk));
//        log.debug("encrypted: {}", HexFormat.of().formatHex(encryptedFmk));
//        log.debug("decrypted: {}", HexFormat.of().formatHex(decrypted));
//    }

    @Test
    void testFmkECCycle() throws GeneralSecurityException, IOException {
        log.trace("testFmkECCycle()");
        byte[] fmk = Crypto.generateFileMasterKey();
        KeyPair aliceKeyPair = loadPkcs11KeyPair();

        KeyPair bobKeyPair = ECKeys.generateEcKeyPair();


//        Provider pkcs11Provider = Security.getProvider("SunPKCS11-OpenSC");
//        KeyAgreement pkcs11Ka = KeyAgreement.getInstance("ECDH", pkcs11Provider);
//        KeyAgreement ka = KeyAgreement.getInstance("ECDH");

        byte[] aliceKek = Crypto.deriveKeyEncryptionKey(aliceKeyPair, (ECPublicKey) bobKeyPair.getPublic(), fmk.length);
        byte[] encryptedFmk = Crypto.xor(fmk, aliceKek);

        byte[] bobKek = Crypto.deriveKeyDecryptionKey(bobKeyPair, (ECPublicKey) aliceKeyPair.getPublic(), fmk.length);
        byte[] decryptedFmk = Crypto.xor(encryptedFmk, bobKek);



        log.debug("FMK:       {}", HexFormat.of().formatHex(fmk));
        log.debug("alice KEK: {}", HexFormat.of().formatHex(aliceKek));
        log.debug("encrypted: {}", HexFormat.of().formatHex(encryptedFmk));
        log.debug("bob KEK:   {}", HexFormat.of().formatHex(bobKek));
        log.debug("decrypted: {}", HexFormat.of().formatHex(decryptedFmk));

        assertArrayEquals(aliceKek, bobKek);
        assertArrayEquals(fmk, decryptedFmk);
    }

}
