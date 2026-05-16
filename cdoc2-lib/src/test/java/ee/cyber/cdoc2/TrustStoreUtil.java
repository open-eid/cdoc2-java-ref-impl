package ee.cyber.cdoc2;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.Resources;


public final class TrustStoreUtil {
    private static final String CERT_NOT_FOUND = "Rp Server trusted SSL certificates not found";
    private static final Logger log = LoggerFactory.getLogger(TrustStoreUtil.class);

    private TrustStoreUtil() {
        // utility class
    }

    public static KeyStore readSidSigningCertificateTrustStore(Cdoc2RpClientConfiguration rpServerClientConfig)
        throws ConfigurationLoadingException {

        try (InputStream is = Resources.getResourceAsStream(
            rpServerClientConfig.getSidSigningCertificateTrustStore(), TrustStoreUtil.class.getClassLoader())
        ) {
            if (null == is) {
                throw new ConfigurationLoadingException(CERT_NOT_FOUND);
            } else {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(
                    is,
                    rpServerClientConfig.getSidSigningCertificateTrustStorePassword().toCharArray()
                );
                return trustStore;
            }
        } catch (CertificateException
                 | IOException
                 | NoSuchAlgorithmException
                 | KeyStoreException ex) {
            throw new ConfigurationLoadingException(
                "Failed to load trusted certificates for Smart ID signing certificate validation",
                ex
            );
        }
    }

    public static KeyStore readMidSidSigningCertificateTrustStore(Cdoc2RpClientConfiguration rpServerClientConfig)
        throws ConfigurationLoadingException {

        try (InputStream is = Resources.getResourceAsStream(
            rpServerClientConfig.getMidSigningCertificateTrustStore(), TrustStoreUtil.class.getClassLoader())
        ) {
            if (null == is) {
                throw new ConfigurationLoadingException(CERT_NOT_FOUND);
            } else {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(
                    is,
                    rpServerClientConfig.getMidSigningCertificateTrustStorePassword().toCharArray()
                );
                return trustStore;
            }
        } catch (CertificateException
                 | IOException
                 | NoSuchAlgorithmException
                 | KeyStoreException ex) {
            throw new ConfigurationLoadingException(
                "Failed to load trusted certificates for Mobile ID signing certificate validation",
                ex
            );
        }
    }
}
