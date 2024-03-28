package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.client.api.ApiClient;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.ApiResponse;
import ee.cyber.cdoc2.client.api.Cdoc2KeyCapsulesApi;
import ee.cyber.cdoc2.client.model.Capsule;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import jakarta.ws.rs.client.ClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client for creating and getting CDOC2 key capsules from key server. Provides Builder to initialize mutual TLS
 * from PKCS11 (smart-card) or PKCS12 (software) key stores.
 */
public final class Cdoc2KeyCapsuleApiClient {
    private static final Logger log = LoggerFactory.getLogger(Cdoc2KeyCapsuleApiClient.class);

    public static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    public static final int DEFAULT_READ_TIMEOUT_MS = 500;

    private final Cdoc2KeyCapsulesApi capsulesApi;


    private Cdoc2KeyCapsuleApiClient(Cdoc2KeyCapsulesApi capsuleApi) {
        this.capsulesApi = capsuleApi;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Cdoc2KeyCapsuleApiClient that = (Cdoc2KeyCapsuleApiClient) o;
        return capsulesApi.equals(that.capsulesApi);
    }

    @Override
    public int hashCode() {
        return Objects.hash(capsulesApi);
    }

    public static final class Builder {
        private static final Logger log = LoggerFactory.getLogger(Builder.class);

        private String baseUrl;
        private KeyStore clientKeyStore;
        private KeyStore.ProtectionParameter clientKeyStoreProtectionParameter;
        private KeyStore trustKeyStore;

        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        private boolean debug = false;
        private String userAgent = "cdoc2-client";


        private Builder() {
        }

        /**
         * Init server base url
         * @param url server base url, example https://host:8443
         * @return
         */
        public Builder withBaseUrl(String url) {
            this.baseUrl = url;
            return this;
        }

        /**
         * Client keystore used for mutual TLS
         * @param clientKS client key store containing client keys for mutual TLS or null, if mTLS is not used
         * @return
         */
        public Builder withClientKeyStore(@Nullable KeyStore clientKS) {
            this.clientKeyStore = clientKS;
            return this;
        }

        public Builder withClientKeyStorePassword(char[] pw) {
            this.clientKeyStoreProtectionParameter = new KeyStore.PasswordProtection(pw);
            return this;
        }

        public Builder withClientKeyStoreProtectionParameter(KeyStore.ProtectionParameter pm) {
            this.clientKeyStoreProtectionParameter = pm;
            return this;
        }

        /**
         * Set trusted key store for client. KeyStore must be already initialized, example:
         * <code>
         * KeyStore trustKeyStore = KeyStore.getInstance("JKS");
         * trustKeyStore.load(Files.newInputStream(Path.of("clienttruststore.jks")),
         *                     "passwd".toCharArray());
         *</code>
         * @param trustKS initialized trusted key store to be used by TLS
         * @return
         */
        public Builder withTrustKeyStore(KeyStore trustKS) {
            this.trustKeyStore = trustKS;
            return this;
        }

        public Builder withConnectTimeoutMs(int timeout) {
            this.connectTimeoutMs = timeout;
            return this;
        }

        public Builder withReadTimeoutMs(int timeout) {
            this.readTimeoutMs = timeout;
            return this;
        }

        public Builder withUserAgent(String ua) {
            this.userAgent = ua;
            return this;
        }

        public Builder withDebuggingEnabled(boolean enabled) {
            this.debug = enabled;
            return this;
        }

        //basic validation
        private void validate() {
            if ((baseUrl == null) || (!baseUrl.startsWith("https://"))) {
                throw new IllegalStateException("baseUrl " + baseUrl + " cannot be null and must start with https://");
            }

            if (trustKeyStore == null) {
                throw new IllegalStateException("TrustKeyStore cannot be null");
            }

            if (clientKeyStore != null && clientKeyStoreProtectionParameter == null) {
                throw new IllegalStateException("ClientKeyStoreProtectionParameter cannot be null");
            }
        }

        public Cdoc2KeyCapsuleApiClient build() throws GeneralSecurityException {
            validate();

            final SSLContext finalSslContext = createSslContext();
            ApiClient apiClient = new ApiClient() {
                @Override
                protected void customizeClientBuilder(ClientBuilder clientBuilder) {
                    if (finalSslContext != null) {
                        clientBuilder.sslContext(finalSslContext);
                    }
                }
            };

            apiClient.setBasePath(this.baseUrl);
            apiClient.setConnectTimeout(connectTimeoutMs);
            apiClient.setReadTimeout(readTimeoutMs);

            apiClient.setDebugging(debug);
            apiClient.addDefaultHeader("Accept", "application/json");
            apiClient.selectHeaderAccept(new String[]{"application/json"});

            apiClient.setUserAgent(userAgent);

            return new Cdoc2KeyCapsuleApiClient(new Cdoc2KeyCapsulesApi(apiClient));
        }

        private SSLContext createSslContext() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
                KeyStoreException, KeyManagementException {
            SSLContext sslContext;
            try {
                TrustManagerFactory trustManagerFactory =
                        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustKeyStore);

                sslContext = SSLContext.getInstance("TLSv1.3");
                sslContext.init(
                    getClientKeyManager().orElse(null),
                    trustManagerFactory.getTrustManagers(),
                    SecureRandom.getInstanceStrong()
                );
            } catch (GeneralSecurityException gse) {
                log.error("Error initializing SSLContext", gse);
                throw gse;
            }
            return sslContext;
        }

        private Optional<KeyManager[]> getClientKeyManager() throws NoSuchAlgorithmException,
                InvalidAlgorithmParameterException {
            if (clientKeyStore == null) {
                return Optional.empty();
            }

            KeyManagerFactory clientKeyManagerFactory =
                KeyManagerFactory.getInstance("PKIX"); //only PKIX supports ManagerFactoryParameters
            log.debug("client key store type: {}", this.clientKeyStore.getType());

            KeyStore.Builder clientKeyStoreBuilder = ("PKCS11".equals(clientKeyStore.getType()))
                ? KeyStore.Builder.newInstance("PKCS11",
                    clientKeyStore.getProvider(), clientKeyStoreProtectionParameter)
                : KeyStore.Builder.newInstance(clientKeyStore, clientKeyStoreProtectionParameter);

            var params = new KeyStoreBuilderParameters(clientKeyStoreBuilder);
            clientKeyManagerFactory.init(params);
            return Optional.of(clientKeyManagerFactory.getKeyManagers());
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * @param capsule
     * @return transactionId
     * @throws ApiException
     */
    public String createCapsule(Capsule capsule) throws ApiException {

        Objects.requireNonNull(capsule);
        Objects.requireNonNull(capsule.getCapsuleType());
        if (capsule.getCapsuleType() == Capsule.CapsuleTypeEnum.UNKNOWN_DEFAULT_OPEN_API) {
            throw new IllegalArgumentException("Illegal capsuleType " + capsule.getCapsuleType());
        }
        Objects.requireNonNull(capsule.getRecipientId());
        Objects.requireNonNull(capsule.getEphemeralKeyMaterial());

        ApiResponse<Void> response = capsulesApi.createCapsuleWithHttpInfo(capsule);
        String locationHeaderValue = null;
        if (response.getStatusCode() == 201
                && response.getHeaders() != null
                && response.getHeaders().containsKey("Location")) {

            List<String> locationHeaders = response.getHeaders().get("Location");
            // expect exactly 1 Location header
            if (locationHeaders.size() == 1) {
                locationHeaderValue = locationHeaders.get(0);
            }
        }

        if (locationHeaderValue == null) {
            log.error("Failed to create ServerEccDetails: {}", response.getStatusCode());
            throw new ApiException(response.getStatusCode(), "Failed to create EccDetails");
        }
        log.debug("Created {}", locationHeaderValue);
        String[] split = locationHeaderValue.split("/");

        if (split.length == 0) {
            throw new IllegalArgumentException("transactionId not present in location header");
        }
        return split[split.length - 1];
    }

    /**
     *
     * @param id
     * @return Optional with value, if server returned 200 or empty Optional if 404
     * @throws ApiException if http response code is something else that 200 or 404
     */
    public Optional<Capsule> getCapsule(String id) throws ApiException {
        if (id == null) {
            throw new IllegalArgumentException("transactionId cannot be null");
        }

        ApiResponse<Capsule> response = capsulesApi.getCapsuleByTransactionIdWithHttpInfo(id);

        switch (response.getStatusCode()) {
            case 200:
                return Optional.of(response.getData());
            case 404:
                return Optional.empty();
            default:
                log.error("Unexpected status code {}", response.getStatusCode());
                throw new ApiException("Unexpected status code " + response.getStatusCode());
        }
    }

}
