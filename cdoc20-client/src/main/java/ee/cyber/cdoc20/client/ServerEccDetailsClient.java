package ee.cyber.cdoc20.client;

import java.io.IOException;
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
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.client.ClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ee.cyber.cdoc20.client.api.ApiClient;
import ee.cyber.cdoc20.client.api.ApiException;
import ee.cyber.cdoc20.client.api.ApiResponse;
import ee.cyber.cdoc20.client.api.EccDetailsApi;
import ee.cyber.cdoc20.client.model.ServerEccDetails;

/**
 * Client for creating and getting ServerEccDetails from key server. Provides Builder to initialize mutual TLS
 * from PKCS11 (smart-card) or PKCS12 (software) key stores.
 */
public final class ServerEccDetailsClient {
    private static final Logger log = LoggerFactory.getLogger(ServerEccDetailsClient.class);

    // prefix to give server details id a 'type', useful for grepping in logs/object database etc,
    // basic format validation
    public static final String SERVER_DETAILS_PREFIX = "SD";

    public static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    public static final int DEFAULT_READ_TIMEOUT_MS = 500;

    private final EccDetailsApi api;

    private ServerEccDetailsClient(EccDetailsApi api) {
        this.api = api;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerEccDetailsClient that = (ServerEccDetailsClient) o;
        return api.equals(that.api);
    }

    @Override
    public int hashCode() {
        return Objects.hash(api);
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
        private String userAgent = "cdoc20-client";


        private Builder() {
        }

        public Builder withBaseUrl(String url) {
            this.baseUrl = url;
            return this;
        }

        public Builder withClientKeyStore(KeyStore clientKS) {
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

            if (clientKeyStore == null) {
                throw new IllegalStateException("ClientKeyStore cannot be null");
            }

        }

        public ServerEccDetailsClient build() throws GeneralSecurityException, IOException {
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

            return new ServerEccDetailsClient(new EccDetailsApi(apiClient));
        }

        private SSLContext createSslContext() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
                KeyStoreException, KeyManagementException {
            SSLContext sslContext = null;
            try {
                KeyManagerFactory clientKeyManagerFactory =
                        KeyManagerFactory.getInstance("PKIX"); //only PKIX supports ManagerFactoryParameters
                log.debug("client key store type: {}", clientKeyStore.getType());

                KeyStore.Builder clientKeyStoreBuilder = ("PKCS11".equals(clientKeyStore.getType()))
                        ? KeyStore.Builder.newInstance("PKCS11",
                                clientKeyStore.getProvider(), clientKeyStoreProtectionParameter)
                        : KeyStore.Builder.newInstance(clientKeyStore, clientKeyStoreProtectionParameter);

                ManagerFactoryParameters clientKeyStoreFactoryParameters =
                        new KeyStoreBuilderParameters(clientKeyStoreBuilder);

                clientKeyManagerFactory.init(clientKeyStoreFactoryParameters);

                TrustManagerFactory trustManagerFactory =
                        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustKeyStore);

                sslContext = SSLContext.getInstance("TLSv1.3");
                sslContext.init(clientKeyManagerFactory.getKeyManagers(),
                        trustManagerFactory.getTrustManagers(), SecureRandom.getInstanceStrong());
            } catch (GeneralSecurityException gse) {
                log.error("Error initializing SSLContext", gse);
                throw gse;
            }
            return sslContext;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public String createEccDetails(ServerEccDetails details) throws ApiException {
        ApiResponse<Void> response = api.createEccDetailsWithHttpInfo(details);

        String locationHeaderValue = null;
        if ((response.getStatusCode() == 201)
                && response.getHeaders() != null
                && response.getHeaders().containsKey("Location")) {

            List<String> locationHeaders = response.getHeaders().get("Location");
            // expect exactly 1 Location header
            if ((locationHeaders.size() == 1)) {
                locationHeaderValue = locationHeaders.get(0);
            }
        }

        if (locationHeaderValue == null) {
            log.error("Failed to create ServerEccDetails: {}", response.getStatusCode());
            throw new ApiException(response.getStatusCode(), "Failed to create EccDetails");
        }
        log.debug("Created {}", locationHeaderValue);
        String[] splitted = locationHeaderValue.split("/");
        String id = splitted[splitted.length - 1];
        if (!id.startsWith(SERVER_DETAILS_PREFIX)) {
            throw new ApiException("Invalid transactionId " + id);
        }

        return id;
    }

    /**
     *
     * @param id
     * @return Optional with value, if server returned 200 or empty Optional if 404
     * @throws ApiException if http response code is something else that 200 or 404
     */
    public Optional<ServerEccDetails> getEccDetailsByTransactionId(String id) throws ApiException {
        if (id == null || !id.startsWith(SERVER_DETAILS_PREFIX)) {
            throw new IllegalArgumentException("Invalid id " + id);
        }

        ApiResponse<ServerEccDetails> response = api.getEccDetailsByTransactionIdWithHttpInfo(id);

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
