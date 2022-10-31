package ee.cyber.cdoc20.util;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.client.ServerEccDetailsClient;
import ee.cyber.cdoc20.client.model.ServerEccDetails;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;

/**
 * KeyServerClient initialization from properties file.
 */
public final class KeyServerPropertiesClient implements KeyServerClient, KeyServerClientFactory {
    private static final Logger log = LoggerFactory.getLogger(KeyServerPropertiesClient.class);

    private final String serverId;

    //TODO: current implementation is using single client for POST and GET. In future there should be two separate
    // clients as baseurls and authentication methods will be different (depends: Server needs DNS addresses and impl).
    private ServerEccDetailsClient client;


    private KeyStore clientKeyStore;

    private KeyServerPropertiesClient(String serverId, ServerEccDetailsClient client, KeyStore clientKeyStore) {
        this.serverId = serverId;
        this.client = client;
        this.clientKeyStore = clientKeyStore;
    }

    public static KeyServerPropertiesClient create(Properties p) throws GeneralSecurityException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("KeyServer properties:");
            p.forEach((key, value) -> log.debug("{}={}", key, value));
        }

        KeyStore clientKeyStore = loadClientKeyStore(p);

        String baseUrl = p.getProperty("cdoc20.client.server.baseurl.post");
        ServerEccDetailsClient.Builder builder = ServerEccDetailsClient.builder()
                .withBaseUrl(baseUrl)
                .withTrustKeyStore(loadTrustKeyStore(p))
                .withClientKeyStore(clientKeyStore)
                .withClientKeyStoreProtectionParameter(loadClientKeyStoreProtectionParamater(p));

        getInteger(p, "cdoc20.client.server.connect-timeout")
                .ifPresent(intValue -> builder.withConnectTimeoutMs(intValue));
        getInteger(p, "cdoc20.client.server.read-timeout")
                .ifPresent(intValue -> builder.withReadTimeoutMs(intValue));
        getBoolean(p, "cdoc20.client.server.debug")
                .ifPresent(b -> builder.withDebuggingEnabled(b));

        ServerEccDetailsClient client = builder.build();

        return new KeyServerPropertiesClient(baseUrl, client, clientKeyStore);
    }

    static KeyStore.ProtectionParameter loadClientKeyStoreProtectionParamater(Properties  p) {
        String prompt = p.getProperty("cdoc20.client.ssl.client-store-password.prompt");
        if (prompt != null) {
            log.debug("Using interactive client KS protection param");
            return ECKeys.getKeyStoreCallbackProtectionParameter(prompt + ":");
        }

        String pw = p.getProperty("cdoc20.client.ssl.client-store-password");
        if (pw != null) {
            log.debug("Using password for client KS");
            return new KeyStore.PasswordProtection(pw.toCharArray());
        }

        return null;
    }

    static Optional<Boolean> getBoolean(Properties p, String name) {
        String value = p.getProperty(name);
        if (value != null) {
            return Optional.of(Boolean.parseBoolean(value));
        }
        return Optional.empty();
    }

    static Optional<Integer> getInteger(Properties p, String name) {
        String value = p.getProperty(name);
        if (value != null) {
            try {
                return Optional.of(Integer.parseInt(value));
            } catch (NumberFormatException nfe) {
                log.warn("Invalid int value {} for property {}. Ignoring.", value, name);
            }
        }
        return Optional.empty();
    }

    /**
     * @param p properties to load the key store
     * @throws KeyStoreException if no Provider supports a KeyStoreSpi implementation for the specified type in
     *      properties file
     * @throws IOException – if an I/O error occurs,
     *      if there is an I/O or format problem with the keystore data,
     *      if a password is required but not given,
     *      or if the given password was incorrect. If the error is due to a wrong password,
     *      the cause of the IOException should be an UnrecoverableKeyException
     * @NoSuchAlgorithmException – if the algorithm used to check the integrity of the keystore cannot be found
     * @CertificateException – if any of the certificates in the keystore could not be loaded
     */
    static KeyStore loadClientKeyStore(Properties p) throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException {
        KeyStore clientKeyStore;

        String type = p.getProperty("cdoc20.client.ssl.client-store.type", "PKCS12");

        if ("PKCS12".equalsIgnoreCase(type)) {
            clientKeyStore = KeyStore.getInstance(type);

            String clientStoreFile = p.getProperty("cdoc20.client.ssl.client-store");
            String passwd = p.getProperty("cdoc20.client.ssl.client-store-password");

            clientKeyStore.load(Resources.getResourceAsStream(clientStoreFile),
                    (passwd != null) ? passwd.toCharArray() : null);

        } else if ("PKCS11".equalsIgnoreCase(type)) {
            String openScLibPath = loadOpenScLibPath(p);
            KeyStore.ProtectionParameter protectionParameter = loadClientKeyStoreProtectionParamater(p);

            // default slot 0 - Isikutuvastus
            clientKeyStore = ECKeys.initPKCS11KeysStore(openScLibPath, null, protectionParameter);
        } else {
            throw new IllegalArgumentException("cdoc20.client.ssl.client-store.type " + type + " not supported");
        }

        return clientKeyStore;
    }

    /**
     * If "opensclibrary" property is set in properties or System properties, return value specified. If both specify
     * value then use one from System properties
     * @param p properties provided
     * @return "opensclibrary" value specified in properties or null if not property not present
     */
    static String loadOpenScLibPath(Properties p) {
        // try to load from System Properties (initialized using -D) and from properties file provided.
        // Give priority to System property
        return System.getProperty(CDocConfiguration.OPENSC_LIBRARY_PROPERTY,
                p.getProperty(CDocConfiguration.OPENSC_LIBRARY_PROPERTY, null));
    }

    /**
     *
     * @param p properties to load the key store
     * @return
     * @throws KeyStoreException if no Provider supports a KeyStoreSpi implementation for the specified type in
     *      properties file
     * @throws IOException – if an I/O error occurs,
     *      if there is an I/O or format problem with the keystore data,
     *      if a password is required but not given,
     *      or if the given password was incorrect. If the error is due to a wrong password,
     *      the cause of the IOException should be an UnrecoverableKeyException
     * @NoSuchAlgorithmException – if the algorithm used to check the integrity of the keystore cannot be found
     * @CertificateException – if any of the certificates in the keystore could not be loaded
     */
    static KeyStore loadTrustKeyStore(Properties p) throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException {
        KeyStore trustKeyStore;

        String type = p.getProperty("cdoc20.client.ssl.trust-store.type", "JKS");

        String trustStoreFile = p.getProperty("cdoc20.client.ssl.trust-store");
        String passwd = p.getProperty("cdoc20.client.ssl.trust-store-password");

        trustKeyStore = KeyStore.getInstance(type);
        trustKeyStore.load(Resources.getResourceAsStream(trustStoreFile),
                (passwd != null) ? passwd.toCharArray() : null);

        return trustKeyStore;

    }

    @Override
    public String storeSenderKey(final ECPublicKey receiverKey, final ECPublicKey senderKey) throws ExtApiException {

        EllipticCurve curve;
        try {
            curve = EllipticCurve.forPubKey(receiverKey);
            EllipticCurve senderCurve = EllipticCurve.forPubKey(senderKey);

            if (curve != senderCurve) {
                throw new IllegalArgumentException("receiverKey and senderKey curves don't match");
            }

        } catch (GeneralSecurityException gse) {
            log.error(gse.toString(), gse);
            throw new ExtApiException(gse);
        }


        ServerEccDetails serverEccDetails = new ServerEccDetails()
                .eccCurve(Integer.valueOf(curve.getValue()))
                .recipientPubKey(ECKeys.encodeEcPubKeyForTls(curve, receiverKey))
                .senderPubKey(ECKeys.encodeEcPubKeyForTls(curve, senderKey));


        try {
            return client.createEccDetails(serverEccDetails);
        } catch (ee.cyber.cdoc20.client.api.ApiException e) {
            throw new ExtApiException(e.getMessage(), e);
        }

    }

    @Override
    public Optional<ECPublicKey> getSenderKey(String transactionId) throws ExtApiException {

        try {
            Optional<ServerEccDetails> serverEccDetailsOptional = client.getEccDetailsByTransactionId(transactionId);
            if (serverEccDetailsOptional.isPresent()) {
                ServerEccDetails serverDetails = serverEccDetailsOptional.get();
                EllipticCurve curve = EllipticCurve.forValue(serverDetails.getEccCurve().byteValue());
                return Optional.of(curve.decodeFromTls(
                        ByteBuffer.wrap(serverDetails.getSenderPubKey())));
            }

            return Optional.empty();

        } catch (GeneralSecurityException gse) {
            log.error("Error decoding key server response ", gse);
            throw new ExtApiException(gse);
        } catch (ee.cyber.cdoc20.client.api.ApiException apiException) {
            throw new ExtApiException(apiException.getMessage(), apiException);
        }
    }

    @Override
    public String getServerIdentifier() {
        return serverId;
    }


    public KeyStore getClientKeyStore() {
        return clientKeyStore;
    }

    @Override
    public KeyServerClient getForId(String serverIdentifier) {
        if (getServerIdentifier().equals(serverIdentifier)) {
            return this;
        }
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyServerPropertiesClient that = (KeyServerPropertiesClient) o;
        return Objects.equals(serverId, that.serverId)
                && Objects.equals(client, that.client)
                && Objects.equals(clientKeyStore, that.clientKeyStore);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverId, client, clientKeyStore);
    }
}
