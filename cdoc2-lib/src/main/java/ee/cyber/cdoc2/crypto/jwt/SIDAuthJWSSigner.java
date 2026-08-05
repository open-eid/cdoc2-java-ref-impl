package ee.cyber.cdoc2.crypto.jwt;

import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.VerificationCodeCalculator;
import ee.sk.smartid.common.InteractionsMapper;
import ee.sk.smartid.common.notification.interactions.NotificationInteraction;
import ee.sk.smartid.util.InteractionUtil;
import jakarta.annotation.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;

import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier;
import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.AuthTokenSignatureValidationParams;
import ee.cyber.cdoc2.client.Cdoc2KeySharesApiClient;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.model.AcspV2Signature;
import ee.cyber.cdoc2.client.model.AuthCertificateLevel;
import ee.cyber.cdoc2.client.model.AuthSignatureProtocol;
import ee.cyber.cdoc2.client.model.AuthSignatureProtocolParameters;
import ee.cyber.cdoc2.client.model.HashAlgorithm;
import ee.cyber.cdoc2.client.model.SessionStatusResponse;
import ee.cyber.cdoc2.client.model.SessionStatusResponseResult;
import ee.cyber.cdoc2.client.model.SidAuthenticateRequest;
import ee.cyber.cdoc2.client.model.SignatureAlgorithm;
import ee.cyber.cdoc2.client.model.SignatureAlgorithmParametersInRequest;
import ee.cyber.cdoc2.client.model.VerificationCodeType;
import ee.cyber.cdoc2.client.rpserver.Cdoc2RpClient;


/**
 * JWSSigner that implements signing using Smart-ID authentication key/certificate
 *
 * @see <a href="https://github.com/SK-EID/smart-id-documentation">SID RP API</a>
 */
public class SIDAuthJWSSigner implements IdentityJWSSigner {
    private static final Logger log = LoggerFactory.getLogger(SIDAuthJWSSigner.class);
    private static final TimeUnit SESSION_POLL_SLEEP_TIMEUNIT = TimeUnit.SECONDS;
    private static final long SESSION_POLL_SLEEP_QUANTITY = 1L;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final JCAContext jcaContext = new JCAContext();

    private final Cdoc2RpClient rpClient;
    private final EtsiIdentifier signerId;
    private final SessionToken sessionToken;

    private final InteractionParams interactionParams;
    private @Nullable String signatureValidationParamsBase64Url = null;

    private X509Certificate signerCertificate = null; // will be initialized with successful sign()

    /**
     * Initialize JWSSigner for signer (format "etsi/PNOEE-37807156011") using pre-initialized Cdoc2RpClient
     *
     * @param rpClient pre-initialized Cdoc2RpClient to use for signing
     * @param signer   Signer identifier in format etsi/PNOEE-37807156011
     * @param params   InteractionParams to drive SID interaction or to get verification code. {@code null} when user is
     *                 not interested in verification code or default interaction behaviour is ok.
     */
    public SIDAuthJWSSigner(EtsiIdentifier signer, Cdoc2RpClient rpClient,
                            InteractionParams params, SessionToken sessionToken) {
        Objects.requireNonNull(rpClient);
        Objects.requireNonNull(signer);

        this.rpClient = rpClient;
        this.signerId = signer;
        this.sessionToken = sessionToken;
        this.interactionParams = params;
    }

    /**
     * Sign signingInput data using Smart-ID RP API. Before returning Smart-ID generated
     * signature is verified using Smart-ID client library.
     *
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

        byte[] rpChallenge = DigestCalculator.calculateDigest(
            signingInput,
            ee.sk.smartid.HashAlgorithm.SHA_256
        );

        String verificationCode = VerificationCodeCalculator.calculate(rpChallenge);

        if (interactionParams != null) {
            AuthEvent authEvent = new AuthEvent(this, verificationCode,
                interactionParams.getDocument());
            interactionParams.notifyAuthListeners(authEvent);
        } else {
            String message = "No interactions on SID signature request";
            log.error(message);
            throw new IllegalStateException(message);
        }

        NotificationInteraction interaction;
        switch (interactionParams.interactionType) {
            case DISPLAY_TEXT_AND_PIN -> {
                interaction =
                    NotificationInteraction.displayTextAndPin(interactionParams.displayText);
            }
            case CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE -> {
                interaction =
                    NotificationInteraction
                        .confirmationMessageAndVerificationCodeChoice(interactionParams.displayText);
            }
            default -> throw new IllegalStateException(
                "Interaction type not implemented: " + interactionParams.interactionType
            );
        }

        String interactionsBase64 =
            InteractionUtil.encodeToBase64(InteractionsMapper.from(List.of(interaction)));

        try {
            String disclosedSessionToken = sessionToken.getSessionToken(rpClient.getBaseUrl());

            SidAuthenticateRequest request = new SidAuthenticateRequest()
                .semanticsIdentifier(signerId.getSemanticsIdentifier())
                .certificateLevel(AuthCertificateLevel.fromValue(rpClient.getCertificateLevel()))
                .signatureProtocol(AuthSignatureProtocol.ACSP_V2)
                .signatureProtocolParameters(new AuthSignatureProtocolParameters()
                    .rpChallenge(rpChallenge)
                    .signatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                    .signatureAlgorithmParameters(
                        new SignatureAlgorithmParametersInRequest()
                            .hashAlgorithm(HashAlgorithm.SHA_256)
                    )
                )
                .interactions(interactionsBase64)
                .vcType(VerificationCodeType.NUMERIC4);

            UUID sessionId = rpClient.sidAuthenticate(
                disclosedSessionToken,
                sessionToken.getSigningCertificate(),
                request
            );

            SessionStatusResponse response = pollForFinalSessionStatus(
                disclosedSessionToken,
                sessionToken.getSigningCertificate(),
                sessionId
            );

            SessionStatusResponseResult result = response.getResult();

            if (result == null || !"OK".equals(result.getEndResult().getValue())) {
                String message = "SID session endResult: "
                    + Optional.ofNullable(result)
                    .map(r -> r.getEndResult().getValue())
                    .orElse("<none>");

                log.error(message);
                throw new ExtApiException(message);
            }

            this.signerCertificate = X509CertUtils.parse(response.getCert().getValue());

            this.signatureValidationParamsBase64Url = createSignatureValidationParams(
                response,
                interactionsBase64
            );

            return Base64URL.encode(response.getSignature().getValue());
        } catch (ExtApiException | InterruptedException | JsonProcessingException e) {
            throw new JOSEException(e);
        }
    }

    private String createSignatureValidationParams(
        SessionStatusResponse response,
        String interactionsBase64
    ) throws JsonProcessingException {
        String interactionsDigest = Base64.getEncoder().encodeToString(
            DigestCalculator.calculateDigest(
                interactionsBase64.getBytes(StandardCharsets.UTF_8),
                ee.sk.smartid.HashAlgorithm.SHA_256
            )
        );

        AcspV2Signature signature = response.getSignature();

        AuthTokenSignatureValidationParams signatureValidationParams =
            new AuthTokenSignatureValidationParams(
                interactionsDigest,
                response.getInteractionTypeUsed().getValue(),
                new SidRpv3SignatureVerifier.SidSignatureParams(
                    Base64.getEncoder().encodeToString(signature.getServerRandom()),
                    signature.getUserChallenge(),
                    signature.getSignatureAlgorithm().getValue(),
                    signature.getFlowType().getValue(),
                    new SidRpv3SignatureVerifier.SignatureAlgorithmParameters(
                        signature.getSignatureAlgorithmParameters().getHashAlgorithm().getValue(),
                        new SidRpv3SignatureVerifier.MaskGenAlgorithm(
                            signature.getSignatureAlgorithmParameters().getMaskGenAlgorithm()
                                .getAlgorithm().getValue(),
                            new SidRpv3SignatureVerifier.MaskGenAlgorithm.Parameters(
                                signature.getSignatureAlgorithmParameters().getMaskGenAlgorithm()
                                    .getParameters().getHashAlgorithm().getValue()
                            )
                        ),
                        signature.getSignatureAlgorithmParameters().getSaltLength(),
                        signature.getSignatureAlgorithmParameters().getTrailerField().getValue()
                    )
                )
            );

        String signatureValidationParamsJson =
            OBJECT_MAPPER.writeValueAsString(signatureValidationParams);

        return Base64.getUrlEncoder().encodeToString(
            signatureValidationParamsJson.getBytes(StandardCharsets.UTF_8)
        );
    }

    private SessionStatusResponse pollForFinalSessionStatus(
        String xCdoc2SessionToken,
        String xCdoc2SessionX5c,
        UUID sessionId
    ) throws InterruptedException, ExtApiException {
        SessionStatusResponse sessionStatus = null;
        while (sessionStatus == null || "RUNNING".equalsIgnoreCase(sessionStatus.getState().getValue())) {
            sessionStatus = rpClient.sidSession(xCdoc2SessionToken, xCdoc2SessionX5c, sessionId);
            if (sessionStatus != null && "COMPLETE".equalsIgnoreCase(sessionStatus.getState().getValue())) {
                break;
            }
            log.debug("Sleeping for {} {}", SESSION_POLL_SLEEP_QUANTITY,
                SESSION_POLL_SLEEP_TIMEUNIT);
            SESSION_POLL_SLEEP_TIMEUNIT.sleep(SESSION_POLL_SLEEP_QUANTITY);
        }
        log.debug("Got final session status response");
        return sessionStatus;
    }

    @Override
    public EtsiIdentifier getSignerIdentifier() {
        return signerId;
    }

    @Nullable
    @Override
    public String getSignatureValidationParamsBase64Url() {
        return signatureValidationParamsBase64Url;
    }

    @Nullable
    @Override
    public Cdoc2KeySharesApiClient.RpCountersignatureParams getRpCountersignatureParams() {
        return null; // Not used for SID
    }

    /**
     * After {@link #sign(JWSHeader, byte[])} has succeeded, signer public certificate can be queried
     *
     * @return signer certificate if {@code sign()} has succeeded, otherwise will be {@code null}
     */
    public @Nullable X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    // current deployed RP API only support PKCS_v1_5 padding?
    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(new JWSAlgorithm(
            "RSASSA-PSS+ACSP_V2"
        ));
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

}
