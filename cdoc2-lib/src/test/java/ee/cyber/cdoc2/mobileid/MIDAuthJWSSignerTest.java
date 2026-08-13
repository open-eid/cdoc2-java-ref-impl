package ee.cyber.cdoc2.mobileid;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.client.RpClient;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.MIDAuthJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.SIDAuthCertData;
import ee.cyber.cdoc2.crypto.jwt.SessionToken;
import ee.cyber.cdoc2.rpserver.RpClientMock;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static ee.cyber.cdoc2.AuthClientMock.SESSION_TOKEN_NONCE_LOCALHOST_BASE64URL;
import static ee.cyber.cdoc2.rpserver.RpClientMock.MID_SIGNING_CERTIFICATE_BASE64URL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


public class MIDAuthJWSSignerTest {
    private static final Logger log = LoggerFactory.getLogger(MIDAuthJWSSignerTest.class);
    private static final String AUD = "https://junit.cdoc2.ria.ee/key-shares/12345/nonce/6789";
    private static final int RP_WIREMOCK_PORT = 7600;
    private static final UUID SESSION_ID = UUID.fromString("3fa85f64-5717-4562-b3fc-2c963f66afa6");

    private RpClientMock rpClientMock;

    @RegisterExtension
    static WireMockExtension rpWiremock = WireMockExtension.newInstance()
        .options(wireMockConfig()
            .httpDisabled(true)
            .httpsPort(RP_WIREMOCK_PORT)
            .keystorePath("wiremock_keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
        )
        .build();

    @BeforeEach
    void setUp() {
        rpClientMock = new RpClientMock(rpWiremock);
    }

    @Tag("net")
    @Test
    void testGenerateJWTWithMIDSignature() throws Exception {
        rpClientMock.stubMidAuthenticate(SESSION_ID);
        rpClientMock.stubMidSession(SESSION_ID);

        RpClient rpClient = MIDTestData.getDemoEnvClient();
        assertNotNull(rpClient);

        SessionToken sessionToken = new SessionToken(
            SESSION_TOKEN_NONCE_LOCALHOST_BASE64URL,
            MID_SIGNING_CERTIFICATE_BASE64URL
        );

        String phoneNumber = MIDTestData.OK_1_PHONE_NUMBER;
        String identityCode = MIDTestData.OK_1_IDENTITY_CODE;

        EtsiIdentifier etsiIdentifier = new EtsiIdentifier("etsi/PNOEE-" + identityCode);
        final String[] verificationCode = {null};
        InteractionParams interactionParams = InteractionParams
            .displayTextAndVCCForDocument("JWSSignerTest::testSignature", null, null)
            .addAuthListener(e -> {
                verificationCode[0] = e.getVerificationCode();
                log.debug("Verification code: {}", verificationCode[0]);
            });

        MIDAuthJWSSigner midJWSSigner
            = new MIDAuthJWSSigner(etsiIdentifier, phoneNumber, rpClient, interactionParams,
            sessionToken
        );

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

        // TODO since the Cdoc2RpApi response is mocked, we would need to implement MID signing
        //  in the mock for the signature verification to work. However, then we would
        //  essentially be testing a test implementation. Consider if that makes sense, else remove.
//        var signerPubKey = ECKey.parse(signerCert).toECPublicKey();

//        SignedJWT parsedJWT = SignedJWT.parse(jwtStr);
//        JWSVerifier jwsVerifier = new ECDSAVerifier(signerPubKey);

//        assertTrue(parsedJWT.verify(jwsVerifier));

        String signerCertSemanticsIdentifier = SIDAuthCertData.parseSemanticsIdentifier(signerCert);
        assertEquals(etsiIdentifier.getSemanticsIdentifier(), signerCertSemanticsIdentifier);
    }

    /**
     * Extract EC public key from certificate
     *
     * @param certificate containing EC public key
     * @return EC public from certificate as JWK
     * @throws JOSEException If an error occurs during encoding or writing
     */
    public static JWK getECPublicKeyJWK(X509Certificate certificate) throws JOSEException {
        return ECKey.parse(certificate).toPublicJWK();
    }

    public static JWK getRSAPublicKeyJWK(X509Certificate certificate) throws JOSEException {
        return RSAKey.parse(certificate).toPublicJWK();
    }
}
