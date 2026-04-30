package ee.cyber.cdoc2.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;

import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.exceptions.CDocUserException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * Utility for initializing open API client and handling API response.
 */
public final class ApiClientUtil {

    private ApiClientUtil() { }

    public static void handleOpenApiException(Exception exception) throws ExtApiException {
        // IOException is the base class for all network related exceptions
        // and openapi client does not operate with files, so we can assume a network error occurred
        if (exception.getCause() instanceof IOException) {
            throw new CDocUserException(UserErrorCode.NETWORK_ERROR, exception.getMessage());
        }
        throw new ExtApiException(exception.getMessage(), exception);
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
            trustKeyStore.load(Resources.getResourceAsStream(trustStoreFile),
                (storePasswd != null) ? storePasswd.toCharArray() : null);

            return trustKeyStore;
        } catch (IOException
                 | CertificateException
                 | NoSuchAlgorithmException
                 | KeyStoreException e) {
            throw new ConfigurationLoadingException("Failed to load key trust store", e);
        }
    }

    public static SSLContext createSslContext(KeyStore trustStore, Logger log)
        throws NoSuchAlgorithmException,
        KeyStoreException,
        KeyManagementException {

        SSLContext sslContext;
        try {
            TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(
                null,
                trustManagerFactory.getTrustManagers(),
                SecureRandom.getInstanceStrong()
            );
        } catch (GeneralSecurityException gse) {
            log.error("Error initializing SSLContext", gse);
            throw gse;
        }
        return sslContext;
    }
}
