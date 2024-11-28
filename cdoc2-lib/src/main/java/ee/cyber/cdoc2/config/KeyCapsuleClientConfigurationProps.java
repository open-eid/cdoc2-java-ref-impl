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
 * @param clientServerConnectTimeout client trust store password
 * @param clientServerReadTimeout client trust store password
 * @param clientServerDebug client trust store password
 * @param clientServerBaseUrlGet client trust store password
 * @param clientServerBaseUrlPost client trust store password
 * @param clientTrustStore client trust store password
 * @param clientKeyStoreType client key store type
 * @param clientKeyStoreFile client key store file path
 * @param clientKeyStorePassword client key store password
 * @param clientKeyStorePwdPrompt client key store password prompt
 * @param pkcs11LibraryPath PKCS11 library path
 */
public record KeyCapsuleClientConfigurationProps(
    String clientServerId,
    Integer clientServerConnectTimeout,
    Integer clientServerReadTimeout,
    Boolean clientServerDebug,
    String clientServerBaseUrlGet,
    String clientServerBaseUrlPost,
    KeyStore clientTrustStore,
    String clientKeyStoreType,
    String clientKeyStoreFile,
    String clientKeyStorePassword,
    String clientKeyStorePwdPrompt,
    String pkcs11LibraryPath
) implements KeyCapsuleClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(KeyCapsuleClientConfigurationProps.class);

    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 500;

    public static KeyCapsuleClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {
        log.debug("Loading configuration for Key Capsule client.");

        var clientServerId = properties.getProperty(CLIENT_SERVER_ID);

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

        var clientKeyStoreType = properties.getProperty(CLIENT_STORE_TYPE, null);
        var clientKeyStoreFile = properties.getProperty(CLIENT_STORE);
        var clientKeyStorePassword = properties.getProperty(CLIENT_STORE_PWD);
        var clientKeyStorePwdPrompt = properties.getProperty(CLIENT_STORE_PWD_PROMPT);
        var pkcs11LibraryPath = properties.getProperty(PKCS11_LIBRARY_PROPERTY, null);

        return new KeyCapsuleClientConfigurationProps(
            clientServerId,
            clientServerConnectTimeout,
            clientServerReadTimeout,
            clientServerDebug,
            clientServerBaseUrlGet,
            clientServerBaseUrlPost,
            clientTrustStore,
            clientKeyStoreType,
            clientKeyStoreFile,
            clientKeyStorePassword,
            clientKeyStorePwdPrompt,
            pkcs11LibraryPath
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
     * @throws ConfigurationLoadingException if failed to load key trust store
     * @return client key store or null if not defined in properties
     */
    @Nullable
    private KeyStore loadClientKeyStore() throws ConfigurationLoadingException {
        KeyStore clientKeyStore;

        if (null == this.clientKeyStoreType) {
            return null;
        }

        if ("PKCS12".equalsIgnoreCase(this.clientKeyStoreType)) {
            clientKeyStore = loadClientTrustKeyStore(
                this.clientKeyStoreFile, this.clientKeyStoreType, this.clientKeyStorePassword
            );
        } else if ("PKCS11".equalsIgnoreCase(this.clientKeyStoreType)) {
            clientKeyStore = loadPkcs11KeyStore();
        } else {
            throw new IllegalArgumentException(
                CLIENT_STORE_TYPE + " " + this.clientKeyStoreType + " not supported"
            );
        }

        return clientKeyStore;
    }

    private KeyStore loadPkcs11KeyStore() {
        String openScLibPath = loadPkcs11LibPath();
        KeyStore.ProtectionParameter protectionParameter
            = loadClientKeyStoreProtectionParameter();
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
     * @return "pkcs11-library" value specified in properties or null if not property not present
     */
    private String loadPkcs11LibPath() {
        // try to load from System Properties (initialized using -D) and from properties file provided.
        // Give priority to System property
        return System.getProperty(PKCS11_LIBRARY_PROPERTY, this.pkcs11LibraryPath);
    }

    private KeyStore.ProtectionParameter loadClientKeyStoreProtectionParameter() {
        if (this.clientKeyStorePwdPrompt != null) {
            log.debug("Using interactive client KS protection param");
            return Pkcs11Tools.getKeyStoreProtectionHandler(this.clientKeyStorePwdPrompt + ":");
        }

        if (this.clientKeyStorePassword != null) {
            log.debug("Using password for client KS");
            return new KeyStore.PasswordProtection(this.clientKeyStorePassword.toCharArray());
        }

        return null;
    }

    @Override
    public String getClientServerId() {
        return clientServerId;
    }

    @Override
    public KeyStore getClientKeyStore() {
        return loadClientKeyStore();
    }

    @Override
    public KeyStore.ProtectionParameter getKeyStoreProtectionParameter() {
        return loadClientKeyStoreProtectionParameter();
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
