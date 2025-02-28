package ee.cyber.cdoc2.client;

import jakarta.ws.rs.client.ClientBuilder;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;
import jakarta.annotation.Nullable;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Builder for API clients {@link Cdoc2KeyCapsuleApiClient} and {@link Cdoc2KeySharesApiClient}.
 */
public abstract class ApiClientBuilder {

    private static final Logger log = LoggerFactory.getLogger(ApiClientBuilder.class);
    public static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    public static final int DEFAULT_READ_TIMEOUT_MS = 500;

    private String baseUrl;
    private KeyStore clientKeyStore;
    private KeyStore.ProtectionParameter clientKeyStoreProtectionParameter;
    private KeyStore trustKeyStore;
    private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
    private int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
    private boolean debug = false;
    private String userAgent = "cdoc2-client";

    // used for monitoring API-s
    private String username;
    private String password;

    /**
     * Init server base url
     * @param url server base url, example {@code https://host:8443}
     * @return Builder for API client
     */
    public ApiClientBuilder withBaseUrl(String url) {
        this.baseUrl = url;
        return this;
    }

    /**
     * Client keystore used for mutual TLS and initialized in {@link Cdoc2KeyCapsuleApiClient} only
     * @param clientKS client key store containing client keys for mutual TLS or null, if mTLS is not used
     * @return Api client builder for Cdoc2KeyCapsuleApiClient
     */
    public ApiClientBuilder withClientKeyStore(@Nullable KeyStore clientKS) {
        this.clientKeyStore = clientKS;
        return this;
    }

    /**
     * Client keystore protection parameter used for mutual TLS and initialized in
     * {@link Cdoc2KeyCapsuleApiClient} only
     */
    public ApiClientBuilder withClientKeyStorePassword(char[] pw) {
        this.clientKeyStoreProtectionParameter = new KeyStore.PasswordProtection(pw);
        return this;
    }

    /**
     * Client keystore protection parameter used for mutual TLS and initialized in
     * {@link Cdoc2KeyCapsuleApiClient} only
     */
    public ApiClientBuilder withClientKeyStoreProtectionParameter(KeyStore.ProtectionParameter pm) {
        this.clientKeyStoreProtectionParameter = pm;
        return this;
    }

    /**
     * Set trusted key store for client. KeyStore must be already initialized, example:
     * <code>
     * KeyStore trustKeyStore = KeyStore.getInstance("JKS");
     * trustKeyStore.load(Files.newInputStream(Path.of("clienttruststore.jks")),
     * "passwd".toCharArray());
     * </code>
     *
     * @param trustKS initialized trusted key store to be used by TLS
     * @return Api client builder
     */
    public ApiClientBuilder withTrustKeyStore(KeyStore trustKS) {
        this.trustKeyStore = trustKS;
        return this;
    }

    public ApiClientBuilder withConnectTimeoutMs(int timeout) {
        this.connectTimeoutMs = timeout;
        return this;
    }

    public ApiClientBuilder withReadTimeoutMs(int timeout) {
        this.readTimeoutMs = timeout;
        return this;
    }

    public ApiClientBuilder withUserAgent(String ua) {
        this.userAgent = ua;
        return this;
    }

    public ApiClientBuilder withDebuggingEnabled(boolean enabled) {
        this.debug = enabled;
        return this;
    }

    /**
     * Used for basic authentication for monitoring API-s
     * @param xUsername username
     * @return Builder for API client
     */
    public ApiClientBuilder withUsername(String xUsername) {
        this.username = xUsername;
        return this;
    }

    /**
     * Used for basic authentication for monitoring API-s
     * @param xPassword password
     * @return Builder for API client
     */
    public ApiClientBuilder withPassword(String xPassword) {
        this.password = xPassword;
        return this;
    }

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

    ee.cyber.cdoc2.client.api.ApiClient createApiClient() throws GeneralSecurityException {

        validate();

        final SSLContext finalSslContext = createSslContext();
        ee.cyber.cdoc2.client.api.ApiClient apiClient = new ee.cyber.cdoc2.client.api.ApiClient() {
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
        apiClient.selectHeaderAccept("application/json");

        apiClient.setUserAgent(userAgent);
        if (username != null && password != null) {
            apiClient.setUsername(username);
            apiClient.setPassword(password);
        }

        return apiClient;
    }

    private SSLContext createSslContext()
        throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException,
        KeyStoreException,
        KeyManagementException {

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

    /**
     * Client manager used for mutual TLS and initialized in {@link Cdoc2KeyCapsuleApiClient} only
     */
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
