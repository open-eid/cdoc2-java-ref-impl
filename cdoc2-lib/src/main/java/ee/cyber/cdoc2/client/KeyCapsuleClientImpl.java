package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.exceptions.CDocUserException;
import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.client.model.Capsule;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc2.util.ApiClientUtil.handleOpenApiException;
import static ee.cyber.cdoc2.util.DurationUtil.getExpiryTime;


/**
 * KeyCapsuleClient initialization from properties file.
 */
public final class KeyCapsuleClientImpl implements KeyCapsuleClient, KeyCapsuleClientFactory {
    private static final Logger log = LoggerFactory.getLogger(KeyCapsuleClientImpl.class);

    private final String serverId;
    private final Cdoc2KeyCapsuleApiClient postClient; // TLS client
    @Nullable
    private final Cdoc2KeyCapsuleApiClient getClient; // mTLS client
    @Nullable
    private KeyStore clientKeyStore; //initialised only from #create(Properties)
    @Nullable
    private Duration capsuleExpiryDuration; //initialised only when #setExpiryDuration() was called

    private KeyCapsuleClientImpl(
        String serverIdentifier,
        Cdoc2KeyCapsuleApiClient postClient,
        @Nullable Cdoc2KeyCapsuleApiClient getClient,
        @Nullable KeyStore clientKeyStore
    ) {
        this.serverId = serverIdentifier;
        this.postClient = postClient;
        this.getClient = getClient;
        this.clientKeyStore = clientKeyStore;
    }

    public static KeyCapsuleClient create(
        String serverIdentifier,
        Cdoc2KeyCapsuleApiClient postClient,
        Cdoc2KeyCapsuleApiClient getClient
    ) {
        return new KeyCapsuleClientImpl(serverIdentifier, postClient, getClient, null);
    }

    public static KeyCapsuleClient create(KeyCapsuleClientConfiguration config)
        throws GeneralSecurityException {
        return create(config, true);
    }

    /**
     * Create KeyCapsulesClient from configuration file
     * @param config key capsule client configuration
     * @param initMutualTlsClient if false then mutual TLS (get-server) client is not initialized.
     *            Useful, when client is only used for creating KeyCapsules (encryption). Initializing mTLS client may
     *            require special hardware (smart-card or crypto token) and/or interaction with the user.
     * <p>
     *            If false and {@link KeyCapsuleClient#getCapsule(String)} is called, then IllegalStateException is
     *            thrown.
     * @return KeyCapsulesClient
     * @throws GeneralSecurityException if client key store loading or client initialization has
     *                                  failed
     */
    public static KeyCapsuleClient create(
        KeyCapsuleClientConfiguration config,
        boolean initMutualTlsClient
    ) throws GeneralSecurityException {
        String serverId = config.getClientServerId();

        var builder = Cdoc2KeyCapsuleApiClient.builder();
        builder.withTrustKeyStore(config.getClientTrustStore());
        
        builder.withConnectTimeoutMs(config.getClientServerConnectTimeout());
        builder.withReadTimeoutMs(config.getClientServerReadTimeout());
        builder.withDebuggingEnabled(config.getClientServerDebug());

        // postClient can be configured with client key store,
        builder.withBaseUrl(config.getClientServerBaseUrlPost());
        Cdoc2KeyCapsuleApiClient postClient = builder.build();

        // client key store configuration required
        Cdoc2KeyCapsuleApiClient getClient = null;
        KeyStore clientKeyStore = null;
        if (initMutualTlsClient) {
            clientKeyStore = config.getClientKeyStore();
            builder.withClientKeyStore(clientKeyStore);
            builder.withClientKeyStoreProtectionParameter(config.getKeyStoreProtectionParameter());
            builder.withBaseUrl(config.getClientServerBaseUrlGet());
            getClient = builder.build();
        }

        return new KeyCapsuleClientImpl(serverId, postClient, getClient, clientKeyStore);
    }

    public static KeyCapsuleClientFactory createFactory(KeyCapsuleClientConfiguration config)
        throws GeneralSecurityException {

        return (KeyCapsuleClientFactory) create(config);
    }

    @Override
    public void setExpiryDuration(Duration duration) {
        this.capsuleExpiryDuration = duration;
    }

    @Override
    public String storeCapsule(Capsule capsule) throws ExtApiException {
        Objects.requireNonNull(postClient);

        String result = null;
        try {
            result = createCapsule(capsule);
        } catch (Exception e) {
            log.error("Failed to create capsule", e);
            handleOpenApiException(e);
        }
        return result;
    }

    private String createCapsule(Capsule capsule) throws ApiException {
        if (null != capsuleExpiryDuration) {
            OffsetDateTime expiryTime = getExpiryTime(capsuleExpiryDuration);
            return postClient.createCapsule(capsule, expiryTime);
        } else {
            return postClient.createCapsule(capsule);
        }
    }

    @Override
    public Optional<Capsule> getCapsule(String id) throws ExtApiException {
        if (getClient == null) {
            throw new IllegalStateException("get-server client not initialized");
        }

        Optional<Capsule> result = Optional.empty();
        try {
            result = getClient.getCapsule(id);
        } catch (Exception e) {
            log.error("Failed to get capsule", e);
            handleOpenApiException(e);
        }
        return result;
    }

    @Override
    public String getServerIdentifier() {
        return serverId;
    }

    /**
     * Get first certificate from clientKeyStore if its initialized
     * @return first certificate from clientKeyStore or null if not found
     */
    @Nullable
    public Certificate getClientCertificate() {
        return getClientCertificate(null);
    }

    @Nullable
    public Certificate getClientCertificate(@Nullable String alias) {
        if (clientKeyStore != null) {
            try {
                if (alias != null) {
                    return clientKeyStore.getCertificate(alias);
                } else {
                    return clientKeyStore.getCertificate(clientKeyStore.aliases().nextElement());
                }
            } catch (KeyStoreException e) {
                log.debug("Error listing certificate aliases", e);
                return null;
            }
        }

        log.debug("clientKeyStore == null: only initialized for #create(Properties)");
        return null;
    }

    @Override
    public KeyCapsuleClient getForId(String serverIdentifier) throws CDocUserException {
        if (getServerIdentifier().equals(serverIdentifier)) {
            return this;
        }
        log.error("Server configuration for {} requested, but {} provided", serverIdentifier, getServerIdentifier());
        throw new CDocUserException(
            UserErrorCode.SERVER_NOT_FOUND,
            String.format("Server configuration for serverId '%s' not found", serverIdentifier)
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyCapsuleClientImpl that = (KeyCapsuleClientImpl) o;
        return Objects.equals(serverId, that.serverId)
            && Objects.equals(postClient, that.postClient)
            && Objects.equals(getClient, that.getClient)
            && Objects.equals(clientKeyStore, that.clientKeyStore);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverId, postClient, getClient, clientKeyStore);
    }

}
