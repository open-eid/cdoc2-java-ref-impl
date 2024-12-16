package ee.cyber.cdoc2.client.mobileid;

import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidAuthenticationIdentity;
import ee.sk.mid.MidClient;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.config.MobileIdClientConfiguration;
import ee.cyber.cdoc2.exceptions.CdocMobileIdClientException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.Resources;


/**
 * Client for communicating with the Mobile ID client API.
 */
public class MobileIdClient {

    private static final Logger log = LoggerFactory.getLogger(MobileIdClient.class);

    private static final String CERT_NOT_FOUND = "Mobile ID trusted SSL certificates not found";

    private final MobileIdClientWrapper mobileIdClientWrapper;

    private final MobileIdClientConfiguration mobileIdClientConfig;

    /**
     * Constructor for Mobile-ID Client
     * @param conf Mobile-ID client configuration
     */
    public MobileIdClient(MobileIdClientConfiguration conf) {
        this.mobileIdClientConfig = conf;
        MidClient midClient = configureMobileIdClient();
        this.mobileIdClientWrapper = new MobileIdClientWrapper(midClient);
    }

    /**
     * Authentication request to Mobile ID client.
     * @param userData user request data
     * @param authenticationHash Base64 encoded hash function output to be signed
     * @return MidAuthenticationIdentity object
     */
    public MidAuthenticationIdentity startAuthentication(
        MobileIdUserData userData,
        MidAuthenticationHashToSign authenticationHash
    ) throws CdocMobileIdClientException {

        // ToDo display verification code and text to the user in RM-4086
        String verificationCode = authenticationHash.calculateVerificationCode();

        MidAuthenticationRequest request = MidAuthenticationRequest.newBuilder()
            .withPhoneNumber(userData.phoneNumber())
            .withNationalIdentityNumber(userData.identityCode())
            .withHashToSign(authenticationHash)
            .withLanguage(mobileIdClientConfig.getDisplayTextLanguage())
            .withDisplayText(mobileIdClientConfig.getDisplayText())
            .withDisplayTextFormat(mobileIdClientConfig.getDisplayTextFormat())
            .build();

        return mobileIdClientWrapper.authenticate(request, authenticationHash);
    }

    /**
     * Mobile ID client configuration
     */
    private MidClient configureMobileIdClient() throws ConfigurationLoadingException {
        KeyStore trustStore = readTrustedCertificates();

        return MidClient.newBuilder()
            .withHostUrl(mobileIdClientConfig.getHostUrl())
            .withRelyingPartyUUID(mobileIdClientConfig.getRelyingPartyUuid())
            .withRelyingPartyName(mobileIdClientConfig.getRelyingPartyName())
            .withTrustStore(trustStore)
            .withLongPollingTimeoutSeconds(mobileIdClientConfig.getLongPollingTimeoutSeconds())
            .withPollingSleepTimeoutSeconds(mobileIdClientConfig.getPollingSleepTimeoutSeconds())
            .build();
    }

    /**
     * Read trusted certificates for Mobile ID client secure TLS transport
     */
    private KeyStore readTrustedCertificates() throws ConfigurationLoadingException {
        try (InputStream is = Resources.getResourceAsStream(
            mobileIdClientConfig.getTrustStore(), this.getClass().getClassLoader())
        ) {
            if (null == is) {
                throw new ConfigurationLoadingException(CERT_NOT_FOUND);
            } else {
                KeyStore trustStore = KeyStore.getInstance(mobileIdClientConfig.getTrustStoreType());
                trustStore.load(is, mobileIdClientConfig.getTrustStorePassword().toCharArray());
                return trustStore;
            }
        } catch (CertificateException
                 | IOException
                 | NoSuchAlgorithmException
                 | KeyStoreException ex) {
            throw new ConfigurationLoadingException(
                "Failed to load trusted certificates for Mobile ID authentication", ex
            );
        }
    }

}
