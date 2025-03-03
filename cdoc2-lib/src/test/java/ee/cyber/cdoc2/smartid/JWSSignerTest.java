package ee.cyber.cdoc2.smartid;

//indirect dependency through cdoc2-auth
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.SIDAuthCertData;
import ee.cyber.cdoc2.crypto.jwt.SIDAuthJWSSigner;
import ee.cyber.cdoc2.services.Cdoc2Services;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;

import static ee.cyber.cdoc2.ClientConfigurationUtil.DEMO_ENV_PROPERTIES;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


class JWSSignerTest {

    private static final Logger log = LoggerFactory.getLogger(JWSSignerTest.class);

    private static final String AUD = "https://junit.cdoc2.ria.ee/key-shares/12345/nonce/6789";

    //demo env 30303039914 that automatically authenticates successfully
    private static final String IDENTITY_NUMBER = "30303039914";

    // SID demo env cert for 30303039914 that automatically authenticates successfully
    private final String sidCertStr = """
        -----BEGIN CERTIFICATE-----
        MIIIIjCCBgqgAwIBAgIQUJQ/xtShZhZmgogesEbsGzANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZ
        QVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNVBAMME1RFU1Qgb2YgRUlE
        LVNLIDIwMTYwIBcNMjQwNzAxMTA0MjM4WhgPMjAzMDEyMTcyMzU5NTlaMGMxCzAJBgNVBAYTAkVFMRYwFAYDVQQDDA1URVNU
        TlVNQkVSLE9LMRMwEQYDVQQEDApURVNUTlVNQkVSMQswCQYDVQQqDAJPSzEaMBgGA1UEBRMRUE5PRUUtMzAzMDMwMzk5MTQw
        ggMiMA0GCSqGSIb3DQEBAQUAA4IDDwAwggMKAoIDAQCo+o1jtKxkNWHvVBRA8Bmh08dSJxhL/Kzmn7WS2u6vyozbF6M3f1lp
        XZXqXqittSmiz72UVj02jtGeu9Hajt8tzR6B4D+DwWuLCvTawqc+FSjFQiEB+wHIb4DrKF4t42Aazy5mlrEy+yMGBe0ygMLd
        6GJmkFw1pzINq8vu6sEY25u6YCPnBLhRRT3LhGgJCqWQvdsN3XCV8aBwDK6IVox4MhIWgKgDF/dh9XW60MMiW8VYwWC7ONa
        3LTqXJRuUhjFxmD29Qqj81k8ZGWn79QJzTWzlh4NoDQT8w+8ZIOnyNBAxQ+Ay7iFR4SngQYUyHBWQspHKpG0dhKtzh3zELIk
        o8sxnBZ9HNkwnIYe/CvJIlqARpSUHY/Cxo8X5upwrfkhBUmPuDDgS14ci4sFBiW2YbzzWWtxbEwiRkdqmA1NxoTJybA9Frj6
        NIjC4Zkk+tL/N8Xdblfn8kBKs+cAjk4ssQPQruSesyvzs4EGNgAk9PX2oeelGTt02AZiVkIpUha8VgDrRUNYyFZc3E3Z3Ph1
        aOCEQMMPDATaRps3iHw/waHIpziHzFAncnUXQDUMLr6tiq+mOlxYCi8+NEzrwT2GOixSIuvZK5HzcJTBYz35+ESLGjxnUjb
        ssfra9RAvyaeE1EDfAOrJNtBHPWP4GxcayCcCuVBK2zuzydhY6Kt8ukXh5MIM08GRGHqj8gbBMOW6zEb3OVNSfyi1xF8MYAT
        KnM1XjSYN49My0BPkJ01xCwFzC2HGXUTyb8ksmHtrC8+MrGLus3M3mKFvKA9VatSeQZ8ILR6WeA54A+GMQeJuV54ZHZtD208
        5Vj7R+IjR+3jakXBvZhVoSTLT7TIIa0U6L46jUIHee/mbf5RJxesZzkP5zA81csYyLlzzNzFah1ff7MxDBi0v/UyJ9ngFCeL
        t7HewtlC8+HRbgSdk+57KgaFIgVFKhv34Hz1Wfh3ze1Rld3r1Dx6so4h4CZOHnUN+hprosI4t1y8jorCBF2GUDbIqmBCx7Dg
        qT6aE5UcMcXd8CAwEAAaOCAckwggHFMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgSwMHkGA1UdIARyMHAwZAYKKwYBBAHOHw
        MRAjBWMFQGCCsGAQUFBwIBFkhodHRwczovL3d3dy5za2lkc29sdXRpb25zLmV1L3Jlc291cmNlcy9jZXJ0aWZpY2F0aW9uLX
        ByYWN0aWNlLXN0YXRlbWVudC8wCAYGBACPegECMB0GA1UdDgQWBBQUFyCLUawSl3KCp22kZI88UhtHvTAfBgNVHSMEGDAWgB
        SusOrhNvgmq6XMC2ZV/jodAr8StDATBgNVHSUEDDAKBggrBgEFBQcDAjB8BggrBgEFBQcBAQRwMG4wKQYIKwYBBQUHMAGGHW
        h0dHA6Ly9haWEuZGVtby5zay5lZS9laWQyMDE2MEEGCCsGAQUFBzAChjVodHRwOi8vc2suZWUvdXBsb2FkL2ZpbGVzL1RFU1
        Rfb2ZfRUlELVNLXzIwMTYuZGVyLmNydDAwBgNVHREEKTAnpCUwIzEhMB8GA1UEAwwYUE5PRUUtMzAzMDMwMzk5MTQtTU9DSy
        1RMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMTkwMzAzMDMxMjAwMDBaMA0GCSqGSIb3DQEBCwUAA4ICAQCqlSMpTx+/n
        wfI5eEislq9rce9eOY/9uA0b3Pi7cn6h7jdFes1HIlFDSUjA4DxiSWSMD0XX1MXe7J7xx/AlhwFI1WKKq3eLx4wE8sjOaacH
        nwV/JSTf6iSYjAB4MRT2iJmvopgpWHS6cAQfbG7qHE19qsTvG7Ndw7pW2uhsqzeV5/hcCf10xxnGOMYYBtU7TheKRQtkeBiP
        Jsv4HuIFVV0pGBnrvpqj56Q+TBD9/8bAwtmEMScQUVDduXPc+uIJJoZfLlUdUwIIfhhMEjSRGnaK4H0laaFHa05+KkFtHzc/
        iYEGwJQbiKvUn35/liWbcJ7nr8uCQSuV4PHMjZ2BEVtZ6Qj58L/wSSidb4qNkSb9BtlK+wwNDjbqysJtQCAKP7SSNuYcEAWl
        mvtHmpHlS3tVb7xjko/a7zqiakjCXE5gIFUmtZJFbG5dO/0VkT5zdrBZJoq+4DkvYSVGVDE/AtKC86YZ6d1DY2jIT0c9Blb
        Fp40A4Xkjjjf5/BsRlWFAs8Ip0Y/evG68gQBATJ2g3vAbPwxvNX2x3tKGNg+aDBYMGM76rRrtLhRqPIE4Ygv8x/s7JoBxy1q
        Czuwu/KmB7puXf/y/BBdcwRHIiBq2XQTfEW3ZJJ0J5+Kq48keAT4uOWoJiPLVTHwUP/UBhwOSa4nSOTAfdBXG4NqMknYwvAE
        9g==
        -----END CERTIFICATE-----
        """;

    @Tag("net")
    @Test
    void testSignature() throws JOSEException, ParseException, GeneralSecurityException {

        EtsiIdentifier signerId = new EtsiIdentifier("etsi/PNOEE-" + IDENTITY_NUMBER);

        SmartIdClient sidClient = Cdoc2Services.initFromProperties(DEMO_ENV_PROPERTIES).get(SmartIdClient.class);

        final String[] verificationCode = {null};

        InteractionParams interactionParams = InteractionParams
            .displayTextAndVCCForDocument("JWSSignerTest::testSignature")
            .addAuthListener(e -> {
                verificationCode[0] = e.getVerificationCode();
                log.debug("Verification code: {}", verificationCode[0]);
            });

        SIDAuthJWSSigner sidJWSSigner = new SIDAuthJWSSigner(signerId, sidClient, interactionParams);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .audience(List.of(AUD))
            .issuer(signerId.toString()) // "etsi/PNOEE-37807156011"
            .build();

        // normally signing certificate is included in header as "x5c" or "x5u", but as SID cert is not available,
        // before successful authentication, then specify "kid" that doesn't have format specified
        SignedJWT signedJWT = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signerId.getSemanticsIdentifier()) // "PNOEE-37807156011"
                .build(),
            claimsSet);

        signedJWT.sign(sidJWSSigner);

        assertNotNull(verificationCode[0]);

        X509Certificate signerCert = sidJWSSigner.getSignerCertificate();

        assertNotNull(signerCert);

        String jwtStr = signedJWT.serialize();

        log.debug("JWT: {}", jwtStr);
        log.debug("Signer cert PEM: {}", X509CertUtils.toPEMString(signerCert));
        log.debug("pub key: {}", SIDAuthCertData.getRSAPublicKeyPkcs1Pem(signerCert));

        RSAPublicKey signerRsaPubKey =  RSAKey.parse(signerCert).toRSAPublicKey();

        SignedJWT parsedJWT = SignedJWT.parse(jwtStr);
        JWSVerifier jwsVerifier = new RSASSAVerifier(signerRsaPubKey);

        assertTrue(parsedJWT.verify(jwsVerifier));

        SIDAuthCertData certData = SIDAuthCertData.parse(signerCert);

        assertEquals(signerId.getSemanticsIdentifier(), certData.getSemanticsIdentifier());

        // authEvent was fired and verificationCode set
        assertNotNull(verificationCode[0]);
    }

    @Test
    void testParseSidCert() throws CertificateException {
        final String expectedRsaPubKeyPem =
        """
        -----BEGIN RSA PUBLIC KEY-----
        MIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAqPqNY7SsZDVh71QUQPAZ
        odPHUicYS/ys5p+1ktrur8qM2xejN39ZaV2V6l6orbUpos+9lFY9No7RnrvR2o7f
        Lc0egeA/g8Friwr02sKnPhUoxUIhAfsByG+A6yheLeNgGs8uZpaxMvsjBgXtMoDC
        3ehiZpBcNacyDavL7urBGNubumAj5wS4UUU9y4RoCQqlkL3bDd1wlfGgcAyuiFaM
        eDISFoCoAxf3YfV1utDDIlvFWMFguzjWty06lyUblIYxcZg9vUKo/NZPGRlp+/UC
        c01s5YeDaA0E/MPvGSDp8jQQMUPgMu4hUeEp4EGFMhwVkLKRyqRtHYSrc4d8xCyJ
        KPLMZwWfRzZMJyGHvwrySJagEaUlB2PwsaPF+bqcK35IQVJj7gw4EteHIuLBQYlt
        mG881lrcWxMIkZHapgNTcaEycmwPRa4+jSIwuGZJPrS/zfF3W5X5/JASrPnAI5OL
        LED0K7knrMr87OBBjYAJPT19qHnpRk7dNgGYlZCKVIWvFYA60VDWMhWXNxN2dz4d
        WjghEDDDwwE2kabN4h8P8GhyKc4h8xQJ3J1F0A1DC6+rYqvpjpcWAovPjRM68E9h
        josUiLr2SuR83CUwWM9+fhEixo8Z1I27LH62vUQL8mnhNRA3wDqyTbQRz1j+BsXG
        sgnArlQSts7s8nYWOirfLpF4eTCDNPBkRh6o/IGwTDlusxG9zlTUn8otcRfDGAEy
        pzNV40mDePTMtAT5CdNcQsBcwthxl1E8m/JLJh7awvPjKxi7rNzN5ihbygPVWrUn
        kGfCC0elngOeAPhjEHibleeGR2bQ9tPOVY+0fiI0ft42pFwb2YVaEky0+0yCGtFO
        i+Oo1CB3nv5m3+UScXrGc5D+cwPNXLGMi5c8zcxWodX3+zMQwYtL/1MifZ4BQni7
        ex3sLZQvPh0W4EnZPueyoGhSIFRSob9+B89Vn4d83tUZXd69Q8erKOIeAmTh51Df
        oaa6LCOLdcvI6KwgRdhlA2yKpgQsew4Kk+mhOVHDHF3fAgMBAAE=
        -----END RSA PUBLIC KEY-----
        """;

        X509Certificate sidCert = PemTools.loadCertificate(
            new ByteArrayInputStream(sidCertStr.getBytes(StandardCharsets.UTF_8)));

        SIDAuthCertData certData = SIDAuthCertData.parse(sidCert);

        // SERIALNUMBER=PNOEE-30303039914, GIVENNAME=OK, SURNAME=TESTNUMBER, CN="TESTNUMBER,OK", C=EE'
        assertEquals("EE", certData.getCountry());
        assertEquals("OK", certData.getGivenName());
        assertEquals("TESTNUMBER", certData.getSurname());
        assertEquals("PNOEE-30303039914", certData.getSemanticsIdentifier());
        assertEquals("30303039914", certData.getIdentityNumber());
        assertEquals(sidCert, certData.getAuthCertificate());
        assertEquals(expectedRsaPubKeyPem.replaceAll("\\s", ""),
                SIDAuthCertData.getRSAPublicKeyPkcs1Pem(sidCert).replaceAll("\\s", ""));
    }

}
