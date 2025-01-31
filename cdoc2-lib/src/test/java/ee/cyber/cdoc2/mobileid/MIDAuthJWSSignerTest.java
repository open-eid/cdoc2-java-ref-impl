package ee.cyber.cdoc2.mobileid;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.jwk.ECKey;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.MIDAuthJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.SIDAuthCertData;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class MIDAuthJWSSignerTest {

    private static final Logger log = LoggerFactory.getLogger(MIDAuthJWSSignerTest.class);

    private static final String AUD = "https://junit.cdoc2.ria.ee/key-shares/12345/nonce/6789";

    @Tag("net")
    @Test
    void testGenerateJWTWithMIDSignature() throws JOSEException, ParseException {
        MobileIdClient mobileIdClient = MIDTestData.getDemoEnvClient();
        assertNotNull(mobileIdClient);

        String phoneNumber = MIDTestData.OK_1_PHONE_NUMBER;
        String identityCode = MIDTestData.OK_1_IDENTITY_CODE;

        EtsiIdentifier etsiIdentifier = new EtsiIdentifier("etsi/PNOEE-" + identityCode);
        final String[] verificationCode = {null};
        InteractionParams interactionParams = InteractionParams
            .displayTextAndVCCForDocument("JWSSignerTest::testSignature")
            .addAuthListener(e -> {
                verificationCode[0] = e.getVerificationCode();
                log.debug("Verification code: {}", verificationCode[0]);
            });


        MIDAuthJWSSigner midJWSSigner
            = new MIDAuthJWSSigner(etsiIdentifier, phoneNumber, mobileIdClient, interactionParams);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .audience(List.of(AUD))
            .issuer(etsiIdentifier.toString()) // "etsi/PNOEE-51307149560"
            .build();

        // normally signing certificate is included in header as "x5c" or "x5u",
        // but for MID certificate is available after signing
        SignedJWT signedJWT = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
            claimsSet);

        signedJWT.sign(midJWSSigner); //calls JWSSigner.sign(JWSHeader, byte[])

        // callback for interactionParams was called
        assertNotNull(verificationCode[0]);

        X509Certificate signerCert = midJWSSigner.getSignerCertificate();
        assertNotNull(signerCert);

        String jwtStr = signedJWT.serialize();

        // to verify at https://sdjwt.org/
        log.debug("JWT: {}", jwtStr);
        log.debug("Signer cert PEM: {}", X509CertUtils.toPEMString(signerCert));
        log.debug("cert issuer {}", signerCert.getIssuerX500Principal());
        log.debug("pub key: {}", getECPublicKeyJWK(signerCert));

        var signerPubKey = ECKey.parse(signerCert).toECPublicKey();

        SignedJWT parsedJWT = SignedJWT.parse(jwtStr);
        JWSVerifier jwsVerifier = new ECDSAVerifier(signerPubKey);

        assertTrue(parsedJWT.verify(jwsVerifier));

        SIDAuthCertData certData = SIDAuthCertData.parse(signerCert);

        assertEquals(etsiIdentifier.getSemanticsIdentifier(), certData.getSemanticsIdentifier());
    }

    /**
     * Extract EC public key from certificate
     * @param certificate containing EC public key
     * @return EC public from certificate as JWK
     * @throws JOSEException If an error occurs during encoding or writing
     */
    public static JWK getECPublicKeyJWK(X509Certificate certificate) throws JOSEException {
        return ECKey.parse(certificate).toPublicJWK();
    }
}
