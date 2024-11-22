package ee.cyber.cdoc2.config;

import jakarta.annotation.Nullable;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.crypto.Pkcs11Tools;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;
import ee.cyber.cdoc2.util.Resources;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getBoolean;


/**
 * Key capsule client configuration properties.
 *
 * @param clientServerId number of key shares servers
 * @param clientKeyStore key shares servers URL-s
 * @param keyStoreProtectionParameter key shares servers URL-s
 * @param clientServerConnectTimeout client trust store password
 * @param clientServerReadTimeout client trust store password
 * @param clientServerDebug client trust store password
 * @param clientServerBaseUrlGet client trust store password
 * @param clientServerBaseUrlPost client trust store password
 * @param clientTrustStore client trust store password
 */
public record KeyCapsuleClientConfigurationProps(
    String clientServerId,
    KeyStore clientKeyStore,
    KeyStore.ProtectionParameter keyStoreProtectionParameter,
    Integer clientServerConnectTimeout,
    Integer clientServerReadTimeout,
    Boolean clientServerDebug,
    String clientServerBaseUrlGet,
    String clientServerBaseUrlPost,
    KeyStore clientTrustStore
) implements KeyCapsuleClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(KeyCapsuleClientConfigurationProps.class);

    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 500;

    public static KeyCapsuleClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading configuration for Key Capsule client.");
        var clientServerId = properties.getProperty(CLIENT_SERVER_ID);
        var clientKeyStore = loadClientKeyStore(properties);
        var keyStoreProtectionParameter = loadClientKeyStoreProtectionParameter(properties);
        int clientServerConnectTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            CLIENT_SERVER_CONNECT_TIMEOUT
        ).orElse(DEFAULT_CONNECT_TIMEOUT_MS);
        int clientServerReadTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            CLIENT_SERVER_READ_TIMEOUT
        ).orElse(DEFAULT_READ_TIMEOUT_MS);
        Boolean clientServerDebug = getBoolean(properties, CLIENT_SERVER_DEBUG).orElse(false);

        var clientServerBaseUrlGet = properties.getProperty(CLIENT_SERVER_BASE_URL_GET);
        var clientServerBaseUrlPost = properties.getProperty(CLIENT_SERVER_BASE_URL_POST);

        var clientTrustStore = loadTrustKeyStore(properties);

        return new KeyCapsuleClientConfigurationProps(
            clientServerId,
            clientKeyStore,
            keyStoreProtectionParameter,
            clientServerConnectTimeout,
            clientServerReadTimeout,
            clientServerDebug,
            clientServerBaseUrlGet,
            clientServerBaseUrlPost,
            clientTrustStore
        );
    }

    /**
     * Loads client key trust store based on properties.
     * @param p properties to load the key store
     * @return Keystore loaded based on properties
     * @throws ConfigurationLoadingException if failed to load key trust store
     */
    private static KeyStore loadTrustKeyStore(Properties p) throws ConfigurationLoadingException {
        String type = p.getProperty(CLIENT_TRUST_STORE_TYPE, "JKS");
        String trustStoreFile = p.getProperty(CLIENT_TRUST_STORE);
        String passwd = p.getProperty(CLIENT_TRUST_STORE_PWD);

        return loadClientTrustKeyStore(trustStoreFile, type, passwd);
    }

    /**
     * Loads client key trust store based on properties.
     * @param trustStoreFile key trust store location path
     * @param storeType trust store type
     * @param storePasswd trust store password
     * @return Keystore loaded based on properties
     * @throws ConfigurationLoadingException if failed to load key trust store
     */
    public static KeyStore loadClientTrustKeyStore(
        String trustStoreFile, String storeType, String storePasswd
    ) throws ConfigurationLoadingException {
        try {
            KeyStore trustKeyStore = KeyStore.getInstance(storeType);
            trustKeyStore.load(
                Resources.getResourceAsStream(trustStoreFile),
                (storePasswd != null) ? storePasswd.toCharArray() : null);

            return trustKeyStore;
        } catch (IOException
                 | CertificateException
                 | NoSuchAlgorithmException
                 | KeyStoreException e) {
            throw new ConfigurationLoadingException("Failed to load key trust store", e);
        }
    }

    /**
     * @param p properties to load the key store
     * @throws ConfigurationLoadingException if failed to load key trust store
     * @return client key store or null if not defined in properties
     */
    @Nullable
    private static KeyStore loadClientKeyStore(Properties p)
        throws ConfigurationLoadingException {

        KeyStore clientKeyStore;
        String type = p.getProperty(CLIENT_STORE_TYPE, null);

        if (null == type) {
            return null;
        }

        if ("PKCS12".equalsIgnoreCase(type)) {
            String clientStoreFile = p.getProperty(CLIENT_STORE);
            String passwd = p.getProperty(CLIENT_STORE_PWD);
            clientKeyStore = loadClientTrustKeyStore(clientStoreFile, type, passwd);
        } else if ("PKCS11".equalsIgnoreCase(type)) {
            clientKeyStore = loadPkcs11KeyStore(p);
        } else {
            throw new IllegalArgumentException(CLIENT_STORE_TYPE + " " + type + " not supported");
        }

        return clientKeyStore;
    }

    private static KeyStore loadPkcs11KeyStore(Properties p) {
        String openScLibPath = loadPkcs11LibPath(p);
        KeyStore.ProtectionParameter protectionParameter = loadClientKeyStoreProtectionParameter(p);
        try {
            // default slot 0 - Isikutuvastus
            return Pkcs11Tools.initPKCS11KeysStore(openScLibPath, null, protectionParameter);
        } catch (KeyStoreException | IOException e) {
            throw new ConfigurationLoadingException("Failed to load PKCS11 key trust store", e);
        }
    }

    /**
     * If "pkcs11-library" property is set in properties or System properties, return value specified.
     * If both specify a value then use one from System properties.
     * @param p properties provided
     * @return "pkcs11-library" value specified in properties or null if not property not present
     */
    private static String loadPkcs11LibPath(Properties p) {
        // try to load from System Properties (initialized using -D) and from properties file provided.
        // Give priority to System property
        return System.getProperty(PKCS11_LIBRARY_PROPERTY,
            p.getProperty(PKCS11_LIBRARY_PROPERTY, null));
    }

    private static KeyStore.ProtectionParameter loadClientKeyStoreProtectionParameter(Properties  p) {
        String prompt = p.getProperty(CLIENT_STORE_PWD_PROMPT);
        if (prompt != null) {
            log.debug("Using interactive client KS protection param");
            return Pkcs11Tools.getKeyStoreProtectionHandler(prompt + ":");
        }

        String pw = p.getProperty(CLIENT_STORE_PWD);
        if (pw != null) {
            log.debug("Using password for client KS");
            return new KeyStore.PasswordProtection(pw.toCharArray());
        }

        return null;
    }

    @Override
    public String getClientServerId() {
        return clientServerId;
    }

    @Override
    public KeyStore getClientKeyStore() {
        return clientKeyStore;
    }

    @Override
    public KeyStore.ProtectionParameter getKeyStoreProtectionParameter() {
        return keyStoreProtectionParameter;
    }

    @Override
    public Integer getClientServerConnectTimeout() {
        return clientServerConnectTimeout;
    }

    @Override
    public Integer getClientServerReadTimeout() {
        return clientServerReadTimeout;
    }

    @Override
    public Boolean getClientServerDebug() {
        return clientServerDebug;
    }

    @Override
    public String getClientServerBaseUrlGet() {
        return clientServerBaseUrlGet;
    }

    @Override
    public String getClientServerBaseUrlPost() {
        return clientServerBaseUrlPost;
    }

    @Override
    public KeyStore getClientTrustStore() {
        return clientTrustStore;
    }

}
