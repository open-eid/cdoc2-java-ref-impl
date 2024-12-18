package ee.cyber.cdoc2.client.smartid;

import ee.sk.smartid.*;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.exceptions.CdocSmartIdClientException;
import ee.cyber.cdoc2.util.Resources;


/**
 * Smart-ID Client
 */
public class SmartIdClientWrapper {

    private static final String CERT_NOT_FOUND = "Smart ID trusted SSL certificates not found";

    private final SmartIdClient sidClient;
    private final SmartIdClientConfiguration smartIdClientConfig;
    private final AuthenticationResponseValidator authenticationResponseValidator;

    /**
     * Constructor for Smart-ID Client wrapper
     * @param conf Smart-ID client configuration
     */
    public SmartIdClientWrapper(SmartIdClientConfiguration conf) {
        this.smartIdClientConfig = conf;
        this.sidClient = configureSmartIdClient(conf);
        this.authenticationResponseValidator = createTrustedCertificatesValidator();
    }

    /**
     * Smart ID client configuration
     * @return SmartIdClient configured smart-id client
     */
    private static SmartIdClient configureSmartIdClient(SmartIdClientConfiguration conf)
        throws ConfigurationLoadingException {

        SmartIdClient client = new SmartIdClient();
        client.setHostUrl(conf.getHostUrl());
        client.setRelyingPartyUUID(conf.getRelyingPartyUuid());
        client.setRelyingPartyName(conf.getRelyingPartyName());
        KeyStore trustedCerts = readTrustedCertificates(conf);
        client.setTrustStore(trustedCerts);

        return client;
    }

    /**
     * Authentication request to {@code /authentication/etsi/:semantics-identifier}.
     * @param semanticsIdentifier ETSI semantics identifier
     * @param authenticationHash  Base64 encoded hash function output to be signed
     * @param certificationLevel  Level of certificate requested, can either be
     *                            {@code QUALIFIED} or {@code ADVANCED}
     * @return SmartIdAuthenticationResponse object
     */
    public SmartIdAuthenticationResponse authenticate(
        SemanticsIdentifier semanticsIdentifier,
        AuthenticationHash authenticationHash,
        String certificationLevel
    ) throws UserAccountNotFoundException,
        UserRefusedException,
        UserSelectedWrongVerificationCodeException,
        SessionTimeoutException,
        DocumentUnusableException,
        ServerMaintenanceException,
        CdocSmartIdClientException {

        SmartIdAuthenticationResponse authResponse = sidClient
            .createAuthentication()
            .withSemanticsIdentifier(semanticsIdentifier)
            .withAuthenticationHash(authenticationHash)
            .withCertificateLevel(certificationLevel)
            // Smart-ID app will display verification code to the user and user must insert PIN1
            .withAllowedInteractionsOrder(
                Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?"))
            )
            // Commented out as EIDPRX fails request parsing when this property is present
            //.withShareMdClientIpAddress(true)
            .authenticate();

        validateResponse(authResponse);

        return authResponse;
    }

    public AuthenticationIdentity validateResponse(
        SmartIdAuthenticationResponse authResponse
    ) throws CdocSmartIdClientException {

        try {
            return authenticationResponseValidator.validate(authResponse);
        } catch (
            UnprocessableSmartIdResponseException | CertificateLevelMismatchException ex
        ) {
            throw new CdocSmartIdClientException(
                "Smart ID authentication response validation has failed", ex
            );
        }
    }

    /**
     * Trusted certificates must be set up to {@link AuthenticationResponseValidator}.
     * @return AuthenticationResponseValidator smart id client validation object
     */
    private AuthenticationResponseValidator createTrustedCertificatesValidator()
        throws ConfigurationLoadingException {
        AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
        for (X509Certificate cert : getTrustedCertificates()) {
            validator.addTrustedCACertificate(cert);
        }

        return validator;
    }

    private List<X509Certificate> getTrustedCertificates() throws ConfigurationLoadingException {
        try {
            KeyStore keystore = readTrustedCertificates();
            Enumeration<String> aliases = keystore.aliases();

            List<X509Certificate> certs = new LinkedList<>();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
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

    private KeyStore readTrustedCertificates() throws ConfigurationLoadingException {
        return readTrustedCertificates(this.smartIdClientConfig);
    }

    /**
     * Read trusted certificates for Smart ID client secure TLS transport
     */
    public static KeyStore readTrustedCertificates(SmartIdClientConfiguration smartIdClientConfig)
        throws ConfigurationLoadingException {

        try (InputStream is = Resources.getResourceAsStream(
            smartIdClientConfig.getTrustStore(), SmartIdClientWrapper.class.getClassLoader())
        ) {
            if (null == is) {
                throw new ConfigurationLoadingException(CERT_NOT_FOUND);
            } else {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(is, smartIdClientConfig.getTrustStorePassword().toCharArray());
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
