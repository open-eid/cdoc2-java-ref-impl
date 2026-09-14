package ee.cyber.cdoc2;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ee.cyber.cdoc2.client.model.AuthCertificateLevel;
import ee.cyber.cdoc2.client.model.AuthSignatureProtocol;
import ee.cyber.cdoc2.client.model.AuthSignatureProtocolParameters;
import ee.cyber.cdoc2.client.model.HashAlgorithm;
import ee.cyber.cdoc2.client.model.MidAuthenticateRequest;
import ee.cyber.cdoc2.client.model.MidDisplayTextFormat;
import ee.cyber.cdoc2.client.model.MidHashType;
import ee.cyber.cdoc2.client.model.MidLanguage;
import ee.cyber.cdoc2.client.model.SidAuthenticateRequest;
import ee.cyber.cdoc2.client.model.SignatureAlgorithm;
import ee.cyber.cdoc2.client.model.SignatureAlgorithmParametersInRequest;
import ee.cyber.cdoc2.client.model.VerificationCodeType;


public final class RpRequestUtil {

    private RpRequestUtil() {
    }

    public static final String EE_SEMANTICS_IDENTIFIER_OK = "PNOEE-40504040001";
    public static final String MID_IDENTIFIER_OK = "51307149560";
    public static final String MID_PHONE_NUMBER = "+37200000000";
    public static final String MID_DISPLAY_TEXT = "Authenticate to decrypt CDOC2 document";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final int RP_CHALLENGE_LENGTH = 64;

    public static SidAuthenticateRequest createSidAuthenticateRequest()
        throws JsonProcessingException {
        var signatureAlgorithmParameters =
            new SignatureAlgorithmParametersInRequest().hashAlgorithm(HashAlgorithm.SHA3_512);

        var signatureProtocolParameters =
            new AuthSignatureProtocolParameters()
                .rpChallenge(createRpChallengeBytes())
                .signatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                .signatureAlgorithmParameters(signatureAlgorithmParameters);

        String interactions = createSidInteractions();
        String interactionsBase64 = Base64.getEncoder().encodeToString(
            interactions.getBytes(StandardCharsets.UTF_8)
        );

        return new SidAuthenticateRequest()
            .semanticsIdentifier(EE_SEMANTICS_IDENTIFIER_OK)
            .certificateLevel(AuthCertificateLevel.QUALIFIED)
            .signatureProtocol(AuthSignatureProtocol.ACSP_V2)
            .signatureProtocolParameters(signatureProtocolParameters)
            .interactions(interactionsBase64)
            .vcType(VerificationCodeType.NUMERIC4);
    }

    private static String createSidInteractions() throws JsonProcessingException {
        ArrayNode array = OBJECT_MAPPER.createArrayNode();

        ObjectNode node1 = OBJECT_MAPPER.createObjectNode();
        node1.put("type", "confirmationMessage");
        node1.put("displayText200", "Decrypting container file \"test.txt\"");
        array.add(node1);

        ObjectNode node2 = OBJECT_MAPPER.createObjectNode();
        node2.put("type", "displayTextAndPIN");
        node2.put("displayText60", "Decrypting container file \"test.txt\"");
        array.add(node2);

        return OBJECT_MAPPER.writeValueAsString(array);
    }

    public static byte[] createRpChallengeBytes() {
        byte[] rpChallengeBytes = new byte[RP_CHALLENGE_LENGTH];
        SECURE_RANDOM.nextBytes(rpChallengeBytes);
        return rpChallengeBytes;
    }

    public static MidAuthenticateRequest createMidAuthenticateRequest() {
        return new MidAuthenticateRequest()
            .phoneNumber(MID_PHONE_NUMBER)
            .nationalIdentityNumber(MID_IDENTIFIER_OK)
            .hash(createRpChallengeBytes())
            .hashType(MidHashType.SHA512)
            .language(MidLanguage.ENG)
            .displayText(MID_DISPLAY_TEXT)
            .displayTextFormat(MidDisplayTextFormat.GSM_7);
    }
}
