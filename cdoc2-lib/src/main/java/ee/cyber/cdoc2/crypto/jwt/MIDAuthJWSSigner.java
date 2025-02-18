package ee.cyber.cdoc2.crypto.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;

import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.client.mobileid.MobileIdUserData;
import ee.cyber.cdoc2.exceptions.CdocMobileIdClientException;
import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidHashToSign;
import ee.sk.mid.MidHashType;

import ee.sk.mid.exception.MidInvalidNationalIdentityNumberException;
import ee.sk.mid.exception.MidInvalidPhoneNumberException;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Set;

/**
 * JWSSigner that implements signing using Mobile-ID authentication key/certificate. Supports only ES256 algorithm.
 * At REST API level signer is identified by "phone number" and "identity code" which is not SematicsIdentifier.
 * @ see <a href="https://github.com/SK-EID/MID">Mobile ID (MID) REST API</a>
 */
public class MIDAuthJWSSigner implements IdentityJWSSigner {

    private static final Logger log = LoggerFactory.getLogger(MIDAuthJWSSigner.class);
    private final JCAContext jcaContext = new JCAContext();

    private final MobileIdClient midClient;
    private final EtsiIdentifier signerEtsiIdentifier;
    private final MobileIdUserData mobileIdUserData;

    private final @Nullable InteractionParams interactionParams;

    private X509Certificate signerCertificate = null; // will be initialized with successful sign()

    /**
     * Initialize JWSSigner with MobileIdClient and signer identified by identity code and phone number
     * and pre-initialized MobileIdClient
     * @param midClient MobileIdClient to perform actual authentication sequence
     * @param signer signer identifier as etsi semantics identifier
     * @param phoneNumber signer phone number in international format e.g. "+3725551234"
     * @param interactionParams  Optional parameters to drive user interaction. {@code null} if not used
     * @throws MidInvalidPhoneNumberException if phone number validation has failed
     * @throws MidInvalidNationalIdentityNumberException if ID code validation has failed
     */
    public MIDAuthJWSSigner(EtsiIdentifier signer, String phoneNumber, MobileIdClient midClient,
                            @Nullable InteractionParams interactionParams) {
        Objects.requireNonNull(midClient);
        Objects.requireNonNull(signer);
        Objects.requireNonNull(phoneNumber);

        this.midClient = midClient;
        this.signerEtsiIdentifier = signer;
        this.mobileIdUserData = new MobileIdUserData(phoneNumber, signer.getIdentifier());
        this.interactionParams = interactionParams;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {

        Objects.requireNonNull(header);
        Objects.requireNonNull(signingInput);

        JWSAlgorithm jwsAlg = header.getAlgorithm();
        if (!supportedJWSAlgorithms().contains(jwsAlg)) {
            throw new JOSEException("JWSAlgorithm " + jwsAlg + " not supported");
        }

        MidAuthenticationHashToSign hash = calcHash(signingInput, toMIDHashType(jwsAlg));

        if (interactionParams != null) {
            AuthEvent authEvent = new AuthEvent(this, hash.calculateVerificationCode(),
                interactionParams.getDocument());
            interactionParams.notifyAuthListeners(authEvent);
        } else {
            log.debug("Verification code: {}", hash.calculateVerificationCode());
        }

        try {
            MidAuthentication result = midClient.startAuthentication(
                mobileIdUserData, hash, interactionParams);
            this.signerCertificate = result.getCertificate();
            return Base64URL.encode(result.getSignatureValue());
        } catch (CdocMobileIdClientException ex) {
            throw new JOSEException(ex);
        }
    }

    @Override
    public EtsiIdentifier getSignerIdentifier() {
        return signerEtsiIdentifier;
    }

    /**
     * After {@link #sign(JWSHeader, byte[])} has succeeded, signer public certificate can be queried
     * @return signer certificate if {@code sign()} has succeeded, otherwise will be {@code null}
     */
    public @Nullable X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public static MidAuthenticationHashToSign calcHash(final byte[] bytesToSign, MidHashType hashType) {

        MidHashToSign hashToSign = MidHashToSign.newBuilder()
            .withDataToHash(bytesToSign)
            .withHashType(hashType)
            .build();
        byte[] hashBytes = hashToSign.getHash();

        return MidAuthenticationHashToSign.newBuilder()
            //.withDataToHash(signingInput) // not implemented for MobileIdAuthenticationHashToSignBuilder
            .withHash(hashBytes)
            .withHashType(hashType)
            .build();
    }

    private MidHashType toMIDHashType(JWSAlgorithm jwsAlg) throws JOSEException {
        // Mobile-ID can use any hash size, but in
        // JWS ES256 is defined as P-256 (secp256r1) curve and SHA-256 hash
        // set hash type so it matches to hash defined in JWT algorithm
        if (JWSAlgorithm.ES256.equals(jwsAlg)) {
            return MidHashType.SHA256;
        } else {
            throw new JOSEException("Unsupported JWSAlgorithm " + jwsAlg);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        // no way to actually check supported algorithms, but in practice MID uses P256
        // some old Mobile-ID certs are in SK LDAP, but latest ones are not
        // some old Mobile-ID accounts also supported additionally RSA with 2K keys size, but EC should be default
        return Set.of(JWSAlgorithm.ES256);
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

}
