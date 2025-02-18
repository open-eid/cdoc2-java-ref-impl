package ee.cyber.cdoc2.crypto.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.exceptions.CdocSmartIdClientException;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdAuthenticationResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nullable;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Set;


/**
 * JWSSigner that implements signing using Smart-ID authentication key/certificate
 * @see <a href="https://github.com/SK-EID/smart-id-documentation">SID RP API</a>
 */
public class SIDAuthJWSSigner implements IdentityJWSSigner {

    public static final String CERT_LEVEL_QUALIFIED = "QUALIFIED";

    private static final Logger log = LoggerFactory.getLogger(SIDAuthJWSSigner.class);

    private final JCAContext jcaContext = new JCAContext();

    private final SmartIdClient sidClient;
    private final EtsiIdentifier signerId;

    private @Nullable InteractionParams interactionParams = null;

    private X509Certificate signerCertificate = null; // will be initialized with successful sign()

    /**
     * Initialize JWSSigner for signer (format "etsi/PNOEE-37807156011") using pre-initialized SmartIdClient
     * @param sidClient pre-initialized SmartIdClient to use for signing
     * @param signer PNOEE-37807156011
     */
    public SIDAuthJWSSigner(EtsiIdentifier signer, SmartIdClient sidClient) {
        Objects.requireNonNull(sidClient);
        Objects.requireNonNull(signer);

        this.sidClient = sidClient;
        this.signerId = signer;
    }

    /**
     * Initialize JWSSigner for signer (format "etsi/PNOEE-37807156011") using pre-initialized SmartIdClient
     * @param sidClient pre-initialized SmartIdClient to use for signing
     * @param signer Signer identifier in format etsi/PNOEE-37807156011
     * @param params InteractionParams to drive SID interaction or to get verification code. {@code null} when user is
     *               not interested in verification code or default interaction behaviour is ok.
     */
    public SIDAuthJWSSigner(EtsiIdentifier signer, SmartIdClient sidClient, @Nullable InteractionParams params) {
        this(signer, sidClient);
        this.interactionParams = params;
    }

    /**
     * Sign signingInput data using Smart-ID RP API. Before returning Smart-ID generated
     * signature is verified using Smart-ID client library.
     * @param header       The JSON Web Signature (JWS) header. Must
     *                     specify a supported JWS algorithm and must not
     *                     be {@code null}.
     * @param signingInput The input to sign. Must not be {@code null}.
     * @return The resulting signature part (third part) of the JWS object.
     * @throws JOSEException If the JWS algorithm is not supported, if a
     *                       critical header parameter is not supported or
     *                       marked for deferral to the application, or if
     *                       signing failed for some other internal reason.
     */
    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
        Objects.requireNonNull(header);
        Objects.requireNonNull(signingInput);

        log.debug("sign {} {}", header, Base64URL.encode(signingInput));

        if (!supportedJWSAlgorithms().contains(header.getAlgorithm())) {
            throw new JOSEException("JWSAlgorithm " + header.getAlgorithm() + " not supported");
        }

        AuthenticationHash hash = calcHash(signingInput, toSIDHashType(header.getAlgorithm()));

        if (interactionParams != null) {
            AuthEvent authEvent = new AuthEvent(this, hash.calculateVerificationCode(),
                interactionParams.getDocument());
            interactionParams.notifyAuthListeners(authEvent);
        } else {
            log.debug("Verification code: {}", hash.calculateVerificationCode());
        }

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(signerId.getSemanticsIdentifier());
        try {
            SmartIdAuthenticationResponse resp = sidClient.authenticate(
                semanticsIdentifier,
                hash,
                CERT_LEVEL_QUALIFIED,
                interactionParams
            );

            this.signerCertificate = resp.getCertificate();

            return Base64URL.encode(resp.getSignatureValue());
        } catch (CdocSmartIdClientException e) {
            throw new JOSEException(e);
        }
    }

    @Override
    public EtsiIdentifier getSignerIdentifier() {
        return signerId;
    }

    /**
     * After {@link #sign(JWSHeader, byte[])} has succeeded, signer public certificate can be queried
     * @return signer certificate if {@code sign()} has succeeded, otherwise will be {@code null}
     */
    public @Nullable X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    /**
     * Calculate <code>hash</code> parameter of `/authentication/etsi/:semantics-identifier` request
     * @param signingInput bytes used to calculate the hash
     * @param hashType SID HashType
     * @return AuthenticationHash calculated from signingInput bytes
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file#2310-authentication-session">
     *     SK RP API v2 /authentication/etsi/:semantics-identifier</a>
     */
    public static AuthenticationHash calcHash(final byte[] signingInput, HashType hashType) {
        AuthenticationHash authenticationHash = new AuthenticationHash();
        byte[] generatedDigest = DigestCalculator.calculateDigest(signingInput, hashType);
        authenticationHash.setHash(generatedDigest);
        authenticationHash.setHashType(hashType);
        return authenticationHash;
    }

    public static HashType toSIDHashType(JWSAlgorithm jwsAlg) throws JOSEException {
        if (JWSAlgorithm.RS256.equals(jwsAlg)) {
            return HashType.SHA256;
        } else {
            throw new JOSEException("Unsupported JWSAlgorithm " + jwsAlg);
        }
    }

    // current deployed RP API only support PKCS_v1_5 padding?
    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.RS256);
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

}
