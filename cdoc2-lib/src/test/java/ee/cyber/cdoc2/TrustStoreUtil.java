package ee.cyber.cdoc2;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.Resources;


public final class TrustStoreUtil {
    private static final String CERT_NOT_FOUND = "Rp Server trusted SSL certificates not found";
    private static final String SID_ISSUER_TRUSTSTORE =
        "classpath:smart-id/smartid_demo_server_trusted_ssl_certs.jks";
    private static final String SID_ISSUER_TRUSTSTORE_PW = "passwd";
    private static final String MID_ISSUER_TRUSTSTORE =
        "classpath:mobile-id/mobileid_demo_server_trusted_ssl_certs.p12";
    private static final String MID_ISSUER_TRUSTSTORE_PW = "passwd";


    private TrustStoreUtil() {
        // utility class
    }

    public static KeyStore readSidSigningCertificateTrustStore()
        throws ConfigurationLoadingException {

        try (InputStream is = Resources.getResourceAsStream(
            SID_ISSUER_TRUSTSTORE, TrustStoreUtil.class.getClassLoader())
        ) {
            if (null == is) {
                throw new ConfigurationLoadingException(CERT_NOT_FOUND);
            } else {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(
                    is,
                    SID_ISSUER_TRUSTSTORE_PW.toCharArray()
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

    public static KeyStore readMidSidSigningCertificateTrustStore()
        throws ConfigurationLoadingException {

        try (InputStream is = Resources.getResourceAsStream(
            MID_ISSUER_TRUSTSTORE, TrustStoreUtil.class.getClassLoader())
        ) {
            if (null == is) {
                throw new ConfigurationLoadingException(CERT_NOT_FOUND);
            } else {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(
                    is,
                    MID_ISSUER_TRUSTSTORE_PW.toCharArray()
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
