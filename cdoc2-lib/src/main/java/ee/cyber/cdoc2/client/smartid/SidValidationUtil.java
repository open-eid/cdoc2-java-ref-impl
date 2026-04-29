package ee.cyber.cdoc2.client.smartid;

import ee.sk.smartid.CertificateValidator;
import ee.sk.smartid.CertificateValidatorImpl;
import ee.sk.smartid.TrustedCACertStore;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.Resources;

/**
 * Validation methods for SID responses
 */
public final class SidValidationUtil {
    private static final String CERT_NOT_FOUND = "Rp Server trusted SSL certificates not found";
    private static final Logger log = LoggerFactory.getLogger(SidValidationUtil.class);

    private SidValidationUtil() {
        // utility class
    }

    private static CertificateValidator createSidCertificateValidator(
        Cdoc2RpClientConfiguration rpServerClientConfig
    ) throws InvalidAlgorithmParameterException, KeyStoreException {
        KeyStore trustStore = readTrustStore(rpServerClientConfig);
        PKIXParameters pkixParameters = new PKIXParameters(trustStore);
        List<X509Certificate> trustedCertificates = getTrustedCertificates(trustStore);

        TrustedCACertStore trustedCACertStore = new TrustedCACertStore() {
            @Override
            public List<X509Certificate> getTrustedCACertificates() {
                return trustedCertificates;
            }

            @Override
            public Set<TrustAnchor> getTrustAnchors() {
                return pkixParameters.getTrustAnchors();
            }

            @Override
            public boolean isOcspEnabled() {
                return false;
            }
        };

        return new CertificateValidatorImpl(trustedCACertStore);
    }

    private static List<X509Certificate> getTrustedCertificates(KeyStore trustStore)
        throws ConfigurationLoadingException {
        try {
            Enumeration<String> aliases = trustStore.aliases();

            List<X509Certificate> certs = new LinkedList<>();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) trustStore.getCertificate(alias);
                certs.add(certificate);
            }

            return certs;
        } catch (KeyStoreException ex) {
            throw new ConfigurationLoadingException(
                "Failed to load trusted certificates for Smart ID authentication "
                    + "response validation", ex
            );
        }
    }

    /**
     * Read trusted certificates for Smart ID client secure TLS transport
     */
    public static KeyStore readTrustStore(Cdoc2RpClientConfiguration rpServerClientConfig)
        throws ConfigurationLoadingException {

        try (InputStream is = Resources.getResourceAsStream(
            rpServerClientConfig.getTrustStore(), SidValidationUtil.class.getClassLoader())
        ) {
            if (null == is) {
                throw new ConfigurationLoadingException(CERT_NOT_FOUND);
            } else {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(is, rpServerClientConfig.getTrustStorePassword().toCharArray());
                return trustStore;
            }
        } catch (CertificateException
                 | IOException
                 | NoSuchAlgorithmException
                 | KeyStoreException ex) {
            throw new ConfigurationLoadingException(
                "Failed to load trusted certificates for Smart ID authentication", ex
            );
        }
    }
}
