package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.Envelope;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.ProviderNotFoundException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Pkcs11Test { //TODO: refactor into single test with soft and pcks11 keys
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
        //String configName = "/etc/opensc/opensc-java.cfg";
//        Path confPath = Crypto.createSunPkcsConfigurationFile(null, null, null);
//        sunPkcs11Provider = Security.getProvider("SunPKCS11").configure(confPath.toString());
//
//        log.debug("Provider name {}", sunPkcs11Provider.getName());
//        log.debug("Provider info {}", sunPkcs11Provider.getInfo());
//        log.debug("Provider properties: {} {}", sunPkcs11Provider.stringPropertyNames());
//
//        // print algorithms available
//        //sunPkcs11Provider.getServices().forEach(s -> log.debug("{} {}",s.getAlgorithm(), s.getType()));
//
//        log.debug("PKCS11 provider available under name: {} {}", sunPkcs11Provider.getName(),
//                (Security.getProvider(sunPkcs11Provider.getName()) != null));
//        Security.addProvider(sunPkcs11Provider);
//        log.debug("PKCS11 provider available under name: {} {}", sunPkcs11Provider.getName(),
//                (Security.getProvider(sunPkcs11Provider.getName()) != null));
//
//
//        log.debug("all providers {}", Arrays.asList(Security.getProviders()).stream().map(p-> p.getName()).toList());
//
//        log.debug("KeyStore.PKCS11 providers {}", Arrays.asList(Security.getProviders("KeyStore.PKCS11")).stream().map(p-> p.getName()).toList());
//        log.debug("KeyAgreement.ECDH providers {}", Arrays.asList(Security.getProviders("KeyAgreement.ECDH")).stream().map(p-> p.getName()).toList());
//



        Path confPath = Crypto.createSunPkcsConfigurationFile(null, null, null);
        Crypto.initSunPkcs11(confPath);
        Provider sun = Security.getProvider(Crypto.getPkcs11ProviderName());
        log.debug("{} provider isConfigured={}", sun.getName(), sun.isConfigured());
        log.debug("PKC11 {}", KeyStore.getInstance("PKCS11", Crypto.getPkcs11ProviderName()).getProvider());
        log.debug("ECDH {}", KeyAgreement.getInstance("ECDH", Crypto.getPkcs11ProviderName()).getProvider());
    }

    KeyPair loadPkcs11KeyPair() throws GeneralSecurityException, IOException{
        String key1 = "Isikutuvastus";
        String pin1 = "3471";

        if (Crypto.getPkcs11ProviderName() == null) {
            throw new ProviderNotFoundException();
        }

        KeyStore ks = KeyStore.getInstance("PKCS11", Crypto.getPkcs11ProviderName());
        ks.load(null, pin1.toCharArray());

        ks.aliases().asIterator().forEachRemaining(alias -> {
            try {
                log.debug("{} key={} cert={}", alias, ks.isKeyEntry(alias), ks.isCertificateEntry(alias));
            } catch (KeyStoreException e) {
                log.error("KeyStoreException", e);
            }
        });

        //can't cast to ECPrivateKey and key.getFormat() and key.getEncoded() return null
        PrivateKey key = (PrivateKey)ks.getKey(key1, pin1.toCharArray());

        log.debug("key encoded: {}", Arrays.toString(key.getEncoded()));
        log.debug("key format: {}", key.getFormat());
        log.debug("key class: {}", key.getClass());
        X509Certificate cert = (X509Certificate)ks.getCertificate(key1);

        log.debug("key: {}", key);
        log.debug("cert: {} ", cert.getSubjectX500Principal().getName());



        return new KeyPair(cert.getPublicKey(), key);
    }

    @Test
    void testContainerUsingPKCS11Key(@TempDir Path tempDir) throws IOException, GeneralSecurityException, CDocParseException {
        log.trace("Pkcs11Test::testContainerUsingPKCS11Key");
        byte[] fmkBuf =  Crypto.generateFileMasterKey();
        KeyPair aliceKeyPair = ECKeys.generateEcKeyPair();
        KeyPair bobKeyPair = loadPkcs11KeyPair();

        log.debug("Using hardware private key for decrypting: {}", Crypto.isPKCS11Key(bobKeyPair.getPrivate() ));

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";

        String payloadData = "payload-" + uuid;

        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);


        ECPublicKey recipientPubKey = (ECPublicKey) bobKeyPair.getPublic();
        List<ECPublicKey> recipients = List.of(recipientPubKey);

        Envelope senderEnvelope = Envelope.prepare(fmkBuf, aliceKeyPair, recipients);
        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(List.of(payloadFile), dst);
            byte[] cdocContainerBytes = dst.toByteArray();

            assertTrue(cdocContainerBytes.length > 0);

            try (ByteArrayInputStream bis = new ByteArrayInputStream(cdocContainerBytes)) {
                List<String> filesExtracted = Envelope.decrypt(bis, bobKeyPair, outDir);

                assertEquals(List.of(payloadFileName), filesExtracted);
                Path payloadPath = Path.of(outDir.toAbsolutePath().toString(), payloadFileName);

                assertEquals(payloadData, Files.readString(payloadPath));
            }
        }
    }


}
