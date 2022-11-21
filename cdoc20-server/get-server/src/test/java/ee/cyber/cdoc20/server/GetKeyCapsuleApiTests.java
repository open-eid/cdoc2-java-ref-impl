package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.client.ServerEccDetailsClient;
import ee.cyber.cdoc20.client.model.Capsule;
import ee.cyber.cdoc20.client.model.ServerEccDetails;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.PemTools;
import ee.cyber.cdoc20.crypto.RsaUtils;
import ee.cyber.cdoc20.util.ExtApiException;
import ee.cyber.cdoc20.util.KeyServerPropertiesClient;
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
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.client.RestTemplate;
import static ee.cyber.cdoc20.server.TestData.getKeysDirectory;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class GetKeyCapsuleApiTests extends BaseIntegrationTest {

    // rest client with client auth using keystore rsa/client-rsa-2048.p12
    @Qualifier("trustAllWithClientAuth")
    @Autowired
    private RestTemplate restTemplate;

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

        var capsule = new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1);

        // Recipient public key TLS encoded and base64 encoded from client-certificate.pem
        File[] certs = {getKeysDirectory().resolve("ca_certs/client-certificate.pem").toFile()};
        ECPublicKey recipientKey = ECKeys.loadCertKeys(certs).get(0);
        ECKeys.EllipticCurve curve = ECKeys.EllipticCurve.forPubKey(recipientKey);
        capsule.recipientId(ECKeys.encodeEcPubKeyForTls(curve, recipientKey));

        // Sender public key
        KeyPair senderKeyPair = curve.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();
        capsule.ephemeralKeyMaterial(ECKeys.encodeEcPubKeyForTls(senderPubKey));

        String id = this.saveCapsule(capsule).getTransactionId();

        assertNotNull(id);

        var serverDetails = client.getEccDetailsByTransactionId(id);

        assertTrue(serverDetails.isPresent());
        assertArrayEquals(capsule.getRecipientId(), serverDetails.get().getRecipientPubKey());
        assertArrayEquals(capsule.getEphemeralKeyMaterial(), serverDetails.get().getSenderPubKey());
        assertEquals((int) ECKeys.EllipticCurve.secp384r1.getValue(), serverDetails.get().getEccCurve());
    }

    @Test
    void testKeyServerPropertiesClientPKCS12() throws ExtApiException, GeneralSecurityException, IOException {
        String prop = "cdoc20.client.server.id=testKeyServerPropertiesClientPKCS12\n";
        prop += "cdoc20.client.server.base-url=" + baseUrl + "\n";
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

        var curve = ECKeys.EllipticCurve.forPubKey(recipientPubKey);

        var capsule = new Capsule()
            .ephemeralKeyMaterial(ECKeys.encodeEcPubKeyForTls(senderPubKey))
            .recipientId(ECKeys.encodeEcPubKeyForTls(curve, recipientPubKey))
            .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1);

        String transactionID = this.saveCapsule(capsule).getTransactionId();

        assertNotNull(transactionID);

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
        String prop = "cdoc20.client.server.id=testKeyServerPropertiesClientPKCS11\n";
        prop += "cdoc20.client.server.base-url=" + baseUrl + "\n";
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

        var curve = ECKeys.EllipticCurve.forPubKey(recipientPubKey);

        var capsule = new Capsule()
            .ephemeralKeyMaterial(ECKeys.encodeEcPubKeyForTls(senderPubKey))
            .recipientId(ECKeys.encodeEcPubKeyForTls(curve, recipientPubKey))
            .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1);

        String id = this.saveCapsule(capsule).getTransactionId();
        assertNotNull(id);

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

        Capsule capsule = new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1);

        // Client public key TLS encoded and base64 encoded from id-kaart
        ECPublicKey pubKey = (ECPublicKey) cert.getPublicKey();
        //recipient must match to client's cert pub key or GET will fail with 404
        capsule.recipientId(ECKeys.encodeEcPubKeyForTls(pubKey));

        KeyPair senderKeyPair = ECKeys.EllipticCurve.secp384r1.generateEcKeyPair();
        ECPublicKey senderPubKey = (ECPublicKey) senderKeyPair.getPublic();
        capsule.ephemeralKeyMaterial(ECKeys.encodeEcPubKeyForTls(senderPubKey));

        String id = this.saveCapsule(capsule).getTransactionId();

        assertNotNull(id);

        Optional<ServerEccDetails> serverDetails = client.getEccDetailsByTransactionId(id);

        assertTrue(serverDetails.isPresent());
        assertArrayEquals(capsule.getRecipientId(), serverDetails.get().getRecipientPubKey());
        assertArrayEquals(capsule.getEphemeralKeyMaterial(), serverDetails.get().getSenderPubKey());
        assertEquals((int) ECKeys.EllipticCurve.secp384r1.getValue(), serverDetails.get().getEccCurve());
    }

    @Test
    void shouldGetRsaCapsule() throws Exception {
        var recipientCert = PemTools.loadCertificate(
            new ByteArrayInputStream(
                Files.readAllBytes(getKeysDirectory().resolve("rsa/client-rsa-2048-cert.pem")
                    .toAbsolutePath())
            )
        );

        var rsaCapsule = new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.RSA)
            .ephemeralKeyMaterial(UUID.randomUUID().toString().getBytes())
            .recipientId(RsaUtils.encodeRsaPubKey((RSAPublicKey) recipientCert.getPublicKey()));

        String txId = this.saveCapsule(rsaCapsule).getTransactionId();

        var response = this.restTemplate.getForEntity(
            new URI(this.capsuleApiUrl() + "/" + txId),
            Capsule.class
        );

        assertNotNull(response);
        assertNotNull(response.getBody());

        assertEquals(rsaCapsule.getCapsuleType(), response.getBody().getCapsuleType());
        assertArrayEquals(rsaCapsule.getRecipientId(), response.getBody().getRecipientId());
        assertArrayEquals(rsaCapsule.getEphemeralKeyMaterial(), response.getBody().getEphemeralKeyMaterial());
    }
}
