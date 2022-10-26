package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.client.ServerEccDetailsClient;
import ee.cyber.cdoc20.client.api.ApiException;
import ee.cyber.cdoc20.client.model.ServerEccDetails;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpa;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpaRepository;
import ee.cyber.cdoc20.util.KeyServerPropertiesClient;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.Properties;
import java.util.random.RandomGenerator;
import javax.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import static ee.cyber.cdoc20.client.ServerEccDetailsClient.SERVER_DETAILS_PREFIX;
import static ee.cyber.cdoc20.server.TestData.getKeysDirectory;
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

    @Autowired
    private ServerEccDetailsJpaRepository jpaRepository;

    @Test
    void testJpaConstraints() {
        ServerEccDetailsJpa model = new ServerEccDetailsJpa();

        model.setEccCurve(1);
        model.setSenderPubKey("123");
        byte[] rnd = new byte[255];
        RandomGenerator.getDefault().nextBytes(rnd);
        model.setRecipientPubKey(Base64.getEncoder().encodeToString(rnd));

        Throwable cause = assertThrows(Throwable.class, () -> jpaRepository.save(model));

        //check that exception is or is caused by ConstraintViolationException
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }

        assertEquals(ConstraintViolationException.class, cause.getClass());
        assertNotNull(cause.getMessage());
        assertTrue(cause.getMessage().contains("'size must be between 0 and 132', propertyPath=recipientPubKey"));
    }

    @Test
    void testJpaSaveAndFindById() {
        assertTrue(postgresContainer.isRunning());

        // test that jpa is up and running (expect no exceptions)
        jpaRepository.count();

        ServerEccDetailsJpa model = new ServerEccDetailsJpa();
        model.setEccCurve(1);

        model.setRecipientPubKey("123");
        model.setSenderPubKey("345");
        ServerEccDetailsJpa saved = jpaRepository.save(model);

        assertNotNull(saved);
        assertNotNull(saved.getTransactionId());

        log.debug("Created {}", saved.getTransactionId());
        Optional<ServerEccDetailsJpa> retrieved = jpaRepository.findById(saved.getTransactionId());
        assertTrue(retrieved.isPresent());
        assertNotNull(retrieved.get().getTransactionId()); // transactionId was generated
        assertTrue(retrieved.get().getTransactionId().startsWith("SD"));
        assertNotNull(retrieved.get().getCreatedAt()); // createdAt field was filled
        log.debug("Retrieved {}", retrieved.get());
    }

    @Test
    void testPKCS12Client() throws Exception {
        ServerEccDetailsClient noAuthClient = ServerEccDetailsClient.builder()
            .withBaseUrl(this.baseUrl)
            .withTrustKeyStore(CLIENT_TRUST_STORE)
            .build();

        var details = new ServerEccDetails();

        // Client public key TLS encoded and base64 encoded from client-certificate.pem
        File[] certs = {getKeysDirectory().resolve("ca_certs/client-certificate.pem").toFile()};
        ECPublicKey recipientKey = ECKeys.loadCertKeys(certs).get(0);
        ECKeys.EllipticCurve curve = ECKeys.EllipticCurve.forPubKey(recipientKey);
        details.recipientPubKey(ECKeys.encodeEcPubKeyForTls(curve, recipientKey));

        // Sender public key
        KeyPair senderKeyPair = curve.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();
        details.senderPubKey(ECKeys.encodeEcPubKeyForTls(senderPubKey));

        details.eccCurve((int) curve.getValue());

        String id = noAuthClient.createEccDetails(details);

        assertNotNull(id);
        assertTrue(id.startsWith(SERVER_DETAILS_PREFIX));

        this.checkCapsuleExistsInDb(id, details);

        // getting the capsule must not succeed without client auth
        assertThrows(ApiException.class, () -> noAuthClient.getEccDetailsByTransactionId(id));
    }

    @Test
    void testKeyServerPropertiesClientPKCS12() throws Exception {
        String prop = "cdoc20.client.server.baseurl.post=" + this.baseUrl + "\n";
        prop += "cdoc20.client.ssl.trust-store.type=JKS\n";
        prop += "cdoc20.client.ssl.trust-store=" + getKeysDirectory().resolve("clienttruststore.jks") + "\n";
        prop += "cdoc20.client.ssl.trust-store-password=passwd\n";

        prop += "cdoc20.client.ssl.client-store.type=PKCS12\n";
        prop += "cdoc20.client.ssl.client-store=" + getKeysDirectory().resolve("cdoc20client.p12") + "\n";
        prop += "cdoc20.client.ssl.client-store-password=passwd\n";

        Properties p = new Properties();
        p.load(new StringReader(prop));

        KeyServerPropertiesClient client = KeyServerPropertiesClient.create(p);

        KeyStore clientKeyStore = client.getClientKeyStore();
        assertEquals(1, clientKeyStore.size());

        X509Certificate cert = (X509Certificate) clientKeyStore.getCertificate(clientKeyStore.aliases().nextElement());

        //recipientPubKey must match with pub key in mutual TLS
        ECPublicKey recipientPubKey = (ECPublicKey) cert.getPublicKey();

        ECPublicKey senderPubKey = (ECPublicKey) ECKeys.EllipticCurve.secp384r1.generateEcKeyPair().getPublic();

        log.debug("Sender pub key: {}",
            Base64.getEncoder().encodeToString(
                ECKeys.encodeEcPubKeyForTls(ECKeys.EllipticCurve.secp384r1, senderPubKey)
            )
        );

        assertNotNull(client.getServerIdentifier());

        String transactionID = client.storeSenderKey(recipientPubKey, senderPubKey);

        assertNotNull(transactionID);
        assertTrue(transactionID.startsWith(SERVER_DETAILS_PREFIX));

        var dbCapsule = this.jpaRepository.findById(transactionID);
        assertTrue(dbCapsule.isPresent());
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
        String prop = "cdoc20.client.server.baseurl.post=" + baseUrl + "\n";
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

        KeyServerPropertiesClient client = KeyServerPropertiesClient.create(p);

        KeyPair senderKeyPair = ECKeys.EllipticCurve.secp384r1.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();

        // Storing clientKeyStore in KeyServerPropertiesClient is a bit of hack for tests.
        // It's required to get recipient pub key
        // normally recipient certificate would come from LDAP, but for test-id card certs are not in LDAP
        KeyStore clientKeyStore = client.getClientKeyStore();
        X509Certificate cert  = (X509Certificate) clientKeyStore.getCertificate("Isikutuvastus");
        // Client public key TLS encoded binary base64 encoded
        ECPublicKey recipientPubKey = (ECPublicKey) cert.getPublicKey();

        String id = client.storeSenderKey(recipientPubKey, senderPubKey);

        assertNotNull(id);
        assertTrue(id.startsWith(SERVER_DETAILS_PREFIX));
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

        ServerEccDetailsClient client = ServerEccDetailsClient.builder()
                .withBaseUrl(baseUrl)
                .withClientKeyStore(clientKeyStore)
                .withClientKeyStoreProtectionParameter(protectionParameter)
                .withTrustKeyStore(trustKeyStore)
                .build();

        ServerEccDetails details = new ServerEccDetails();

        // Client public key TLS encoded and base64 encoded from id-kaart
        ECPublicKey pubKey = (ECPublicKey) cert.getPublicKey();
        //recipient must match to client's cert pub key or GET will fail with 404
        details.recipientPubKey(ECKeys.encodeEcPubKeyForTls(pubKey));

        KeyPair senderKeyPair = ECKeys.EllipticCurve.secp384r1.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();
        details.senderPubKey(ECKeys.encodeEcPubKeyForTls(senderPubKey));

        details.eccCurve(1);

        String id = client.createEccDetails(details);

        assertNotNull(id);
        assertTrue(id.startsWith(SERVER_DETAILS_PREFIX));

        this.checkCapsuleExistsInDb(id, details);
    }

    private void checkCapsuleExistsInDb(String txId, ServerEccDetails expected) {
        var dbCapsuleOpt = this.jpaRepository.findById(txId);
        assertTrue(dbCapsuleOpt.isPresent());
        var dbCapsule = dbCapsuleOpt.get();

        assertEquals(expected.getEccCurve(), dbCapsule.getEccCurve());
        assertEquals(
            Base64.getEncoder().encodeToString(expected.getRecipientPubKey()),
            dbCapsule.getRecipientPubKey()
        );
        assertEquals(
            Base64.getEncoder().encodeToString(expected.getSenderPubKey()),
            dbCapsule.getSenderPubKey()
        );
    }
}
