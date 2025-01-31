package ee.cyber.cdoc2.client.mobileid;

import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidClient;
import ee.sk.mid.MidDisplayTextFormat;
import ee.sk.mid.MidHashToSign;
import ee.sk.mid.MidLanguage;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import jakarta.annotation.Nullable;
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

    // protected to allow overriding MobileIdClient to allow more control over interaction
    protected final MobileIdClientWrapper mobileIdClientWrapper;

    // protected to allow overriding MobileIdClient to allow more control over interaction
    protected final MobileIdClientConfiguration mobileIdClientConfig;

    /**
     * Constructor for Mobile-ID Client
     * @param conf Mobile-ID client configuration
     */
    public MobileIdClient(MobileIdClientConfiguration conf) {
        this.mobileIdClientConfig = conf;
        MidClient midClient = configureMobileIdClient();
        this.mobileIdClientWrapper = new MobileIdClientWrapper(midClient);

    }

    protected MobileIdClient(MobileIdClientConfiguration conf, MobileIdClientWrapper wrapper) {
        this.mobileIdClientConfig = conf;
        this.mobileIdClientWrapper = wrapper;
    }

    /**
     * Authentication request to Mobile ID client. Returns raw MidAuthentication that contains MidSignature and signing
     * Certificate
     * @param userData user request data
     * @param authenticationHash Base64 encoded hash function output to be signed
     * @param interactionParams Optional  parameters to drive user interaction and to get verification code.
     *                          {@code null} when not in use
     * @return MidAuthentication object that contains MidSignature and Certificate
     */
    public MidAuthentication startAuthentication(
        MobileIdUserData userData,
        MidHashToSign authenticationHash,
        @Nullable InteractionParams interactionParams
    ) throws CdocMobileIdClientException {

        MidAuthenticationRequest request = MidAuthenticationRequest.newBuilder()
            .withPhoneNumber(userData.phoneNumber())
            .withNationalIdentityNumber(userData.identityCode())
            .withHashToSign(authenticationHash)
            .withLanguage(getLanguage(interactionParams))
            .withDisplayText(getDisplayText(interactionParams))
            .withDisplayTextFormat(getEncoding(interactionParams))
            .build();

        return mobileIdClientWrapper.authenticate(request, authenticationHash);
    }

    /**
     * Get MID language from interactionParams if defined, otherwise get default value from configuration
     */
    protected MidLanguage getLanguage(@Nullable InteractionParams interactionParams) {
        MidLanguage lang = mobileIdClientConfig.getDefaultDisplayTextLanguage();
        if (interactionParams != null) {
            String iLang = interactionParams.getLanguage();
            if (iLang != null) {
                try {
                    lang = MidLanguage.valueOf(iLang);
                } catch (IllegalArgumentException e) {
                    log.warn("Illegal MidLanguage value, using {}", lang, e);
                }
            }
        }
        return lang;
    }

    /**
     * Get MidDisplayTextFormat from interactionParams if defined, otherwise get default value from configuration
     */
    protected MidDisplayTextFormat getEncoding(@Nullable InteractionParams interactionParams) {
        MidDisplayTextFormat enc = mobileIdClientConfig.getDefaultDisplayTextFormat();
        if (interactionParams != null) {
            String iEnc = interactionParams.getEncoding();
            if (iEnc != null) {
                try {
                    enc = MidDisplayTextFormat.valueOf(iEnc);
                } catch (IllegalArgumentException e) {
                    log.warn("Illegal MidDisplayTextFormat value, using {}", enc, e);
                }
            }
        }

        return enc;
    }

    /** Get displayText from interactionParams if defined, otherwise get default value from configuration */
    protected String getDisplayText(@Nullable InteractionParams interactionParams) {

        // Mobile-ID doesn't support interactionType and text length is limited to 100 bytes -
        // 50 chars for UCS2 and 100 chars for GSM7
        // https://github.com/SK-EID/MID?tab=readme-ov-file#323-request-parameters

        String textAndPIN = mobileIdClientConfig.getDefaultDisplayText();
        if (interactionParams != null) {
                textAndPIN = (getEncoding(interactionParams) == MidDisplayTextFormat.GSM7)
                    ? interactionParams.getDisplayText(100) // GSM7
                    : interactionParams.getDisplayText(50); // UCS2
        }
        return textAndPIN;
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
    public KeyStore readTrustedCertificates() throws ConfigurationLoadingException {
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
