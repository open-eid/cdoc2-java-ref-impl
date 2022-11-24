package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.client.Cdoc20KeyCapsuleApiClient;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.PemTools;
import ee.cyber.cdoc20.crypto.RsaUtils;
import ee.cyber.cdoc20.server.model.Capsule;
import ee.cyber.cdoc20.server.model.db.KeyCapsuleDb;
import ee.cyber.cdoc20.client.EcCapsuleClientImpl;
import ee.cyber.cdoc20.client.ExtApiException;
import ee.cyber.cdoc20.client.KeyCapsuleClient;
import ee.cyber.cdoc20.client.KeyCapsuleClientImpl;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Properties;
import java.util.UUID;

import ee.cyber.cdoc20.client.RsaCapsuleClientImpl;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import static ee.cyber.cdoc20.server.TestData.getKeysDirectory;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class CreateKeyCapsuleTests extends BaseIntegrationTest {
    private static final KeyStore CLIENT_TRUST_STORE = TestData.loadKeyStore(
        "JKS",
        getKeysDirectory().resolve("clienttruststore.jks"),
        "passwd"
    );

    @Qualifier("trustAllNoClientAuth")
    @Autowired
    private RestTemplate restTemplate;

    @Test
    void shouldCreateEcCapsuleUsingPKCS12Client() throws Exception {
        Cdoc20KeyCapsuleApiClient noAuthClient = Cdoc20KeyCapsuleApiClient.builder()
            .withBaseUrl(this.baseUrl)
            .withTrustKeyStore(CLIENT_TRUST_STORE)
            .build();

        EcCapsuleClientImpl client = new EcCapsuleClientImpl(
                KeyCapsuleClientImpl.create("shouldCreateEcCapsuleUsingPKCS12Client", noAuthClient, noAuthClient));

        // Client public key TLS encoded and base64 encoded from client-certificate.pem
        File[] certs = {getKeysDirectory().resolve("ca_certs/client-certificate.pem").toFile()};
        ECPublicKey recipientKey = ECKeys.loadCertKeys(certs).get(0);
        ECKeys.EllipticCurve curve = ECKeys.EllipticCurve.forPubKey(recipientKey);

        var expected = new KeyCapsuleDb();
        expected.setRecipient(ECKeys.encodeEcPubKeyForTls(curve, recipientKey));

        // Sender public key
        KeyPair senderKeyPair = curve.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();
        expected.setPayload(ECKeys.encodeEcPubKeyForTls(senderPubKey));

        expected.setCapsuleType(KeyCapsuleDb.CapsuleType.valueOf(curve.getName().toUpperCase()));

        String id = client.storeSenderKey(recipientKey, senderPubKey);

        assertNotNull(id);

        this.checkCapsuleExistsInDb(id, expected);

        // getting the capsule must not succeed without client auth
        assertThrows(ExtApiException.class, () -> client.getSenderKey(id));
    }


    @Test
    void shouldCreateCapsuleUsingKeyServerPropertiesClientPKCS12() throws Exception {
        String prop = "cdoc20.client.server.id=testKeyServerPropertiesClientPKCS12\n";
        prop += "cdoc20.client.server.base-url.post=" + this.baseUrl + "\n";
        prop += "cdoc20.client.server.base-url.get=" + this.baseUrl + "\n";
        prop += "cdoc20.client.ssl.trust-store.type=JKS\n";
        prop += "cdoc20.client.ssl.trust-store=" + getKeysDirectory().resolve("clienttruststore.jks") + "\n";
        prop += "cdoc20.client.ssl.trust-store-password=passwd\n";

        Properties p = new Properties();
        p.load(new StringReader(prop));

        //use KeyCapsulesClientImpl directly to get access to client public certificate loaded using properties file
        KeyCapsuleClientImpl client = (KeyCapsuleClientImpl) KeyCapsuleClientImpl.create(p);

        File[] certs = {getKeysDirectory().resolve("ca_certs/client-certificate.pem").toFile()};
        ECPublicKey recipientPubKey = ECKeys.loadCertKeys(certs).get(0);

        ECPublicKey senderPubKey = (ECPublicKey) ECKeys.EllipticCurve.secp384r1.generateEcKeyPair().getPublic();

        log.debug("Sender pub key: {}",
            Base64.getEncoder().encodeToString(
                ECKeys.encodeEcPubKeyForTls(ECKeys.EllipticCurve.secp384r1, senderPubKey)
            )
        );

        assertNotNull(client.getServerIdentifier());

        String transactionID = new EcCapsuleClientImpl(client).storeSenderKey(recipientPubKey, senderPubKey);

        assertNotNull(transactionID);

        var dbCapsule = this.capsuleRepository.findById(transactionID);
        assertTrue(dbCapsule.isPresent());
    }

    @Test
    void shouldCreateRsaCapsuleUsingPKCS12Client() throws Exception {
        String prop = "cdoc20.client.server.id=shouldCreateRsaCapsuleUsingPKCS12Client\n";
        prop += "cdoc20.client.server.base-url.post=" + this.baseUrl + "\n";
        prop += "cdoc20.client.server.base-url.get=" + this.baseUrl + "\n";
        prop += "cdoc20.client.ssl.trust-store.type=JKS\n";
        prop += "cdoc20.client.ssl.trust-store=" + getKeysDirectory().resolve("clienttruststore.jks") + "\n";
        prop += "cdoc20.client.ssl.trust-store-password=passwd\n";


        Properties p = new Properties();
        p.load(new StringReader(prop));

        KeyCapsuleClient client = KeyCapsuleClientImpl.create(p);

        assertNotNull(client.getServerIdentifier());


        X509Certificate cert = PemTools.loadCertificate(
                        Files.newInputStream(getKeysDirectory().resolve("rsa/client-rsa-2048-cert.pem")));

        RSAPublicKey rsaPublicKey = (RSAPublicKey) cert.getPublicKey();
        byte[] kek = new byte[Crypto.FMK_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(kek);

        byte[] encryptedKek = RsaUtils.rsaEncrypt(kek, rsaPublicKey);

        String transactionID = new RsaCapsuleClientImpl(client).storeRsaCapsule(rsaPublicKey, encryptedKek);

        assertNotNull(transactionID);

        var dbCapsule = this.capsuleRepository.findById(transactionID);
        assertTrue(dbCapsule.isPresent());

        assertEquals(KeyCapsuleDb.CapsuleType.RSA, dbCapsule.get().getCapsuleType());
        assertArrayEquals(encryptedKek, dbCapsule.get().getPayload());
    }


    @Test
    @Tag("pkcs11")
    void testKeyServerPropertiesClientPKCS11Passwd() throws Exception {
        testKeyServerPropertiesClientPKCS11(false);
    }

    @Test
    @Tag("pkcs11")
    @Disabled("Requires user interaction. Needs to be run separately from other PKCS11 tests as SunPKCS11 caches "
            + "passwords ")
    void testKeyServerPropertiesClientPKCS11Prompt() throws Exception {
        if (System.console() == null) {
            //SpringBootTest sets headless to true and causes graphic dialog to fail, when running inside IDE
            System.setProperty("java.awt.headless", "false");
        }

        testKeyServerPropertiesClientPKCS11(true);
    }

    void testKeyServerPropertiesClientPKCS11(boolean interactive) throws Exception {
        String prop = "cdoc20.client.server.id=testKeyServerPropertiesClientPKCS11\n";
        prop += "cdoc20.client.server.base-url.post=" + this.baseUrl + "\n";
        prop += "cdoc20.client.server.base-url.get=" + this.baseUrl + "\n";
        prop += "cdoc20.client.ssl.trust-store.type=JKS\n";
        prop += "cdoc20.client.ssl.trust-store=" + getKeysDirectory().resolve("clienttruststore.jks") + "\n";
        prop += "cdoc20.client.ssl.trust-store-password=passwd\n";

        prop += "cdoc20.client.ssl.client-store.type=PKCS11\n";

        if (interactive) {
            prop += "cdoc20.client.ssl.client-store-password.prompt=PIN1\n";
        } else {
            prop += "cdoc20.client.ssl.client-store-password=3471\n";
        }

        Properties p = new Properties();
        p.load(new StringReader(prop));

        KeyCapsuleClientImpl client = (KeyCapsuleClientImpl) KeyCapsuleClientImpl.create(p);

        KeyPair senderKeyPair = ECKeys.EllipticCurve.secp384r1.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();

        // Storing clientKeyStore in KeyCapsulesClientImpl is a bit of hack for tests.
        // normally recipient certificate would come from LDAP, but for test-id card certs are not in LDAP
        X509Certificate cert  = (X509Certificate) client.getClientCertificate("Isikutuvastus");
        assertNotNull(cert);

        // Client public key TLS encoded binary base64 encoded
        ECPublicKey recipientPubKey = (ECPublicKey) cert.getPublicKey();

        String id = new EcCapsuleClientImpl(client).storeSenderKey(recipientPubKey, senderPubKey);

        assertNotNull(id);
    }

    @Test
    @Tag("pkcs11")
    void testPKCS11Client() throws Exception {

        //PIN1 for 37101010021 test id-kaart
        var protectionParameter = new KeyStore.PasswordProtection("3471".toCharArray());

        //Or ask pin interactively
        //KeyStore.ProtectionParameter protectionParameter = getKeyStoreCallbackProtectionParameter("PIN1");

        KeyStore clientKeyStore = null;
        KeyStore trustKeyStore = null;
        try {
            clientKeyStore = ECKeys.initPKCS11KeysStore(null, null, protectionParameter);

            trustKeyStore = KeyStore.getInstance("JKS");
            trustKeyStore.load(Files.newInputStream(getKeysDirectory().resolve("clienttruststore.jks")),
                    "passwd".toCharArray());

        }  catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            log.error("Error initializing key stores", e);
        }

        log.debug("aliases: {}", Collections.list(clientKeyStore.aliases()));


        X509Certificate cert  = (X509Certificate) clientKeyStore.getCertificate("Isikutuvastus");
        log.debug("Certificate issuer is {}.  This must be in server truststore "
                + "or SSL handshake will fail with cryptic error", cert.getIssuerDN());

        Cdoc20KeyCapsuleApiClient mTlsClient = Cdoc20KeyCapsuleApiClient.builder()
                .withBaseUrl(baseUrl)
                .withClientKeyStore(clientKeyStore)
                .withClientKeyStoreProtectionParameter(protectionParameter)
                .withTrustKeyStore(trustKeyStore)
                .build();

        //recipient must match to client's cert pub key or GET will fail with 404
        ECPublicKey recipientPubKey = (ECPublicKey) cert.getPublicKey();

        ECKeys.EllipticCurve curve = ECKeys.EllipticCurve.forPubKey(recipientPubKey);
        KeyPair senderKeyPair = curve.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();



        String id = new EcCapsuleClientImpl(KeyCapsuleClientImpl
                .create("testPKCS11Client", null, mTlsClient))
                .storeSenderKey(recipientPubKey, senderPubKey);

        assertNotNull(id);

        KeyCapsuleDb expected = new KeyCapsuleDb();
        expected.setCapsuleType(KeyCapsuleDb.CapsuleType.SECP384R1);
        expected.setRecipient(ECKeys.encodeEcPubKeyForTls(curve, recipientPubKey));
        expected.setPayload(ECKeys.encodeEcPubKeyForTls(curve, senderPubKey));

        this.checkCapsuleExistsInDb(id, expected);
    }

    private void checkCapsuleExistsInDb(String txId, KeyCapsuleDb expected) {
        var dbCapsuleOpt = this.capsuleRepository.findById(txId);
        assertTrue(dbCapsuleOpt.isPresent());
        var dbCapsule = dbCapsuleOpt.get();

        assertEquals(KeyCapsuleDb.CapsuleType.SECP384R1, dbCapsule.getCapsuleType());
        assertArrayEquals(expected.getRecipient(), dbCapsule.getRecipient());
        assertArrayEquals(expected.getPayload(), dbCapsule.getPayload());
    }

    @Test
    void shouldValidateCapsule() {
        var invalidCapsules = Arrays.asList(
            // empty capsule
            new Capsule(),

            // invalid recipient EC pub key
            new Capsule()
                .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1)
                .recipientId(UUID.randomUUID().toString().getBytes())
                .ephemeralKeyMaterial(UUID.randomUUID().toString().getBytes()),

            // invalid RSA pub key
            new Capsule()
                .capsuleType(Capsule.CapsuleTypeEnum.RSA)
                .recipientId(UUID.randomUUID().toString().getBytes())
                .ephemeralKeyMaterial(UUID.randomUUID().toString().getBytes())
        );

        invalidCapsules.forEach(capsule -> assertThrows(
            HttpClientErrorException.BadRequest.class,
            () -> this.restTemplate.postForEntity(this.capsuleApiUrl(), capsule, Void.class)
        ));
    }

    @Test
    void shouldCreateRsaCapsule() throws Exception {
        var rsaCapsule = new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.RSA)
            .ephemeralKeyMaterial(UUID.randomUUID().toString().getBytes());

        var rsaCerts = Arrays.asList(
            "rsa/client-rsa-2048-cert.pem",
            "rsa/client-rsa-4096-cert.pem",
            "rsa/client-rsa-8192-cert.pem",
            "rsa/client-rsa-16384-cert.pem"
        );

        for (String certFile: rsaCerts) {
            var bytes = Files.readAllBytes(getKeysDirectory().resolve(certFile).toAbsolutePath());
            var rsaCert = PemTools.loadCertificate(new ByteArrayInputStream(bytes));

            rsaCapsule.recipientId(RsaUtils.encodeRsaPubKey((RSAPublicKey) rsaCert.getPublicKey()));

            log.info("Creating RSA capsule for {}", certFile);

            var location = this.restTemplate.postForLocation(new URI(this.capsuleApiUrl()), rsaCapsule);
            assertNotNull(location);
        }
    }
}
