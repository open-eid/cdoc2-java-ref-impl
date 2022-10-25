package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.client.ServerEccDetailsClient;
import ee.cyber.cdoc20.client.model.ServerEccDetails;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpa;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpaRepository;
import ee.cyber.cdoc20.util.ExtApiException;
import ee.cyber.cdoc20.util.KeyServerPropertiesClient;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
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
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import static ee.cyber.cdoc20.client.ServerEccDetailsClient.SERVER_DETAILS_PREFIX;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Starts server on https with mutual TLS configured (client must use correct client certificate)
// Starts PostgreSQL running on docker
// Runs integration tests between server and client
@ExtendWith(SpringExtension.class)
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = { "management.server.port=0" }
)
@Testcontainers
@ContextConfiguration(initializers = {ServerEccDetailsIntegrationTest.Initializer.class})
class ServerEccDetailsIntegrationTest {
    private static final Logger log = LoggerFactory.getLogger(ServerEccDetailsIntegrationTest.class);

    @Value("https://localhost:${local.server.port}")
    String baseUrl;

    // start PostgreSQL on Docker container
    @Container
    private static final PostgreSQLContainer postgresContainer = new PostgreSQLContainer("postgres:11.1")
        .withDatabaseName("integration-tests-db")
        .withUsername("sa")
        .withPassword("sa");

    static class Initializer
            implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        public void initialize(ConfigurableApplicationContext configurableApplicationContext) {
            TestPropertyValues.of(
                    "spring.datasource.url=" + postgresContainer.getJdbcUrl(),
                    "spring.datasource.username=" + postgresContainer.getUsername(),
                    "spring.datasource.password=" + postgresContainer.getPassword()
            ).applyTo(configurableApplicationContext.getEnvironment());
        }
    }

    @Autowired
    private ServerEccDetailsJpaRepository jpaRepository;

    static Path getKeysDirectory() throws IOException {
        Properties prop = new Properties();
        //generated during maven generate-test-resources phase, see pom.xml
        prop.load(ServerEccDetailsIntegrationTest.class.getClassLoader().getResourceAsStream("test.properties"));
        String keysProperty = prop.getProperty("cdoc20.keys.dir");
        Path keysPath = Path.of(keysProperty).normalize();
        log.debug("Loading keys/certs from {}", keysPath);
        return keysPath;
    }

    @Test
    void contextLoads() {
        // tests that server is configured properly (no exceptions means success)
    }

    @Test
    void testServerEccDetailsJpaConstraints() {
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
    void testPKCS12Client() throws GeneralSecurityException, IOException, ee.cyber.cdoc20.client.api.ApiException {
        KeyStore clientKeyStore = null;
        KeyStore trustKeyStore = null;
        try {
            clientKeyStore = KeyStore.getInstance("PKCS12");
            clientKeyStore.load(Files.newInputStream(getKeysDirectory().resolve("cdoc20client.p12")),
                    "passwd".toCharArray());
            clientKeyStore.aliases().asIterator().forEachRemaining(a -> log.debug("client KS alias: {}", a));

            trustKeyStore = KeyStore.getInstance("JKS");
            trustKeyStore.load(Files.newInputStream(getKeysDirectory().resolve("clienttruststore.jks")),
                    "passwd".toCharArray());
            trustKeyStore.aliases().asIterator().forEachRemaining(a -> log.debug("client trust KS alias: {}", a));
        }  catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            log.error("Error initializing key stores", e);
        }

        ServerEccDetailsClient client = ServerEccDetailsClient.builder()
                .withBaseUrl(baseUrl)
                .withClientKeyStore(clientKeyStore)
                .withClientKeyStorePassword("passwd".toCharArray())
                .withTrustKeyStore(trustKeyStore)
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

        String id = client.createEccDetails(details);

        assertNotNull(id);
        assertTrue(id.startsWith(SERVER_DETAILS_PREFIX));

        var serverDetails = client.getEccDetailsByTransactionId(id);

        assertTrue(serverDetails.isPresent());
        assertEquals(details, serverDetails.get());
    }

    @Test
    void testKeyServerPropertiesClientPKCS12() throws ExtApiException, GeneralSecurityException, IOException {
        String prop = "cdoc20.client.server.baseurl.post=" + baseUrl + "\n";
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

        Optional<ECPublicKey> serverSenderKey = client.getSenderKey(transactionID);
        assertTrue(serverSenderKey.isPresent());
        assertEquals(senderPubKey, serverSenderKey.get());
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

        Optional<ECPublicKey> serverSenderKey = client.getSenderKey(id);

        assertTrue(serverSenderKey.isPresent());
        assertEquals(senderPubKey, serverSenderKey.get());
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

        Optional<ServerEccDetails> serverDetails = client.getEccDetailsByTransactionId(id);

        assertTrue(serverDetails.isPresent());
        assertEquals(details, serverDetails.get());
    }
}
