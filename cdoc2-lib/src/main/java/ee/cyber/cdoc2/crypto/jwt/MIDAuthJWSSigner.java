package ee.cyber.cdoc2.crypto.jwt;

import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidHashToSign;
import ee.sk.mid.MidHashType;
import ee.sk.mid.exception.MidInvalidNationalIdentityNumberException;
import ee.sk.mid.exception.MidInvalidPhoneNumberException;
import jakarta.annotation.Nullable;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;

import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.client.Cdoc2KeySharesApiClient;
import ee.cyber.cdoc2.client.api.ApiResponse;
import ee.cyber.cdoc2.client.mobileid.MobileIdUserData;
import ee.cyber.cdoc2.client.model.MidSessionStatusResponse;
import ee.cyber.cdoc2.client.rpserver.Cdoc2RpClient;
import ee.cyber.cdoc2.exceptions.CdocRpClientException;

/**
 * JWSSigner that implements signing using Mobile-ID authentication key/certificate. Supports only ES256 algorithm.
 * At REST API level signer is identified by "phone number" and "identity code" which is not SematicsIdentifier.
 *
 * @ see <a href="https://github.com/SK-EID/MID">Mobile ID (MID) REST API</a>
 */
public class MIDAuthJWSSigner implements IdentityJWSSigner {
    private static final TimeUnit SESSION_POLL_SLEEP_TIMEUNIT = TimeUnit.SECONDS;
    private static final long SESSION_POLL_SLEEP_QUANTITY = 1L;

    private static final Logger log = LoggerFactory.getLogger(MIDAuthJWSSigner.class);
    private final JCAContext jcaContext = new JCAContext();

    private final Cdoc2RpClient rpClient;
    private final EtsiIdentifier signerEtsiIdentifier;
    private final MobileIdUserData mobileIdUserData;
    private final SessionToken sessionToken;

    private final @Nullable InteractionParams interactionParams;

    private X509Certificate signerCertificate = null; // will be initialized with successful sign()
    private Cdoc2KeySharesApiClient.RpCountersignatureParams countersignatureParams = null;

    /**
     * Initialize JWSSigner with MobileIdClient and signer identified by identity code and phone number
     * and pre-initialized MobileIdClient
     *
     * @param rpClient          RP client to perform actual authentication sequence
     * @param signer            signer identifier as etsi semantics identifier
     * @param phoneNumber       signer phone number in international format e.g. "+3725551234"
     * @param interactionParams Optional parameters to drive user interaction. {@code null} if not used
     * @throws MidInvalidPhoneNumberException            if phone number validation has failed
     * @throws MidInvalidNationalIdentityNumberException if ID code validation has failed
     */
    public MIDAuthJWSSigner(
        EtsiIdentifier signer,
        String phoneNumber,
        Cdoc2RpClient rpClient,
        @Nullable InteractionParams interactionParams,
        SessionToken sessionToken
    ) {
        Objects.requireNonNull(rpClient);
        Objects.requireNonNull(signer);
        Objects.requireNonNull(phoneNumber);

        this.rpClient = rpClient;
        this.signerEtsiIdentifier = signer;
        this.mobileIdUserData = new MobileIdUserData(phoneNumber, signer.getIdentifier());
        this.interactionParams = interactionParams;
        this.sessionToken = sessionToken;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {

        Objects.requireNonNull(header);
        Objects.requireNonNull(signingInput);

        JWSAlgorithm jwsAlg = header.getAlgorithm();
        if (!supportedJWSAlgorithms().contains(jwsAlg)) {
            throw new JOSEException("JWSAlgorithm " + jwsAlg + " not supported");
        }

        MidHashType midHashType = toMIDHashType(jwsAlg);
        MidAuthenticationHashToSign hash = calcHash(signingInput, midHashType);

        if (interactionParams != null) {
            AuthEvent authEvent = new AuthEvent(this, hash.calculateVerificationCode(),
                interactionParams.getDocument());
            interactionParams.notifyAuthListeners(authEvent);
        } else {
            log.debug("Verification code: {}", hash.calculateVerificationCode());
        }

        try {
            String disclosedSessionToken = sessionToken.getSessionToken(rpClient.getBaseUrl());

            UUID sessionId = rpClient.midAuthenticate(
                disclosedSessionToken,
                sessionToken.getSigningCertificate(),
                mobileIdUserData.identityCode(),
                mobileIdUserData.phoneNumber(),
                hash.getHash(),
                midHashType.toString(),
                interactionParams
            );

            ApiResponse<MidSessionStatusResponse> apiResponse = pollForFinalSessionStatus(
                disclosedSessionToken,
                sessionToken.getSigningCertificate(),
                sessionId
            );

            MidSessionStatusResponse responseBody = apiResponse.getData();

            String result = Optional.ofNullable(responseBody.getResult())
                .map(MidSessionStatusResponse.ResultEnum::getValue)
                .orElse(null);

            if (!"OK".equals(result)) {
                String message = "SID session endResult: " + result;
                log.error(message);
                throw new CdocRpClientException(message);
            }

            this.countersignatureParams = mapCountersignatureHeaders(apiResponse);

            this.signerCertificate = X509CertUtils.parse(responseBody.getCert());

            return Base64URL.encode(responseBody.getSignature().getValue());
        } catch (CdocRpClientException ex) {
            throw new JOSEException(ex);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private Cdoc2KeySharesApiClient.RpCountersignatureParams mapCountersignatureHeaders(
        ApiResponse<MidSessionStatusResponse> apiResponse
    ) {
        Map<String, List<String>> headers = apiResponse.getHeaders();
        return new Cdoc2KeySharesApiClient.RpCountersignatureParams(
            Optional.ofNullable(headers.get("x-rp-signed-hash").get(0))
                .orElseThrow(),
            Optional.ofNullable(headers.get("x-rp-name").get(0))
                .orElseThrow(),
            Optional.ofNullable(headers.get("Signature-Input").get(0))
                .orElseThrow(),
            Optional.ofNullable(headers.get("Signature").get(0))
                .orElseThrow()
        );
    }

    private ApiResponse<MidSessionStatusResponse> pollForFinalSessionStatus(
        String xCdoc2SessionToken,
        String xCdoc2SessionX5c,
        UUID sessionId
    ) throws InterruptedException, CdocRpClientException {
        ApiResponse<MidSessionStatusResponse> response = null;
        while (response == null || "RUNNING".equalsIgnoreCase(response.getData().getState().getValue())) {
            response =
                rpClient.midSession(xCdoc2SessionToken, xCdoc2SessionX5c, sessionId);
            if (response != null && "COMPLETE".equalsIgnoreCase(response.getData().getState().getValue())) {
                break;
            }
            log.debug("Sleeping for {} {}", SESSION_POLL_SLEEP_QUANTITY,
                SESSION_POLL_SLEEP_TIMEUNIT);
            SESSION_POLL_SLEEP_TIMEUNIT.sleep(SESSION_POLL_SLEEP_QUANTITY);
        }
        log.debug("Got final session status response");
        return response;
    }

    @Override
    public EtsiIdentifier getSignerIdentifier() {
        return signerEtsiIdentifier;
    }

    /**
     * After {@link #sign(JWSHeader, byte[])} has succeeded, signer public certificate can be queried
     *
     * @return signer certificate if {@code sign()} has succeeded, otherwise will be {@code null}
     */
    public @Nullable X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    /**
     * Not used for MID signatures
     *
     * @return null
     */
    @Nullable
    @Override
    public String getSignatureValidationParamsBase64Url() {
        return null;
    }

    @Nullable
    @Override
    public Cdoc2KeySharesApiClient.RpCountersignatureParams getRpCountersignatureParams() {
        return countersignatureParams;
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
