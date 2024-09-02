package ee.cyber.cdoc2.cli.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;


class SecretParamTest {

    @Test
    void testSecretParam() {
        final String param = "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=";
        byte[] expectedSecretBytes = Base64.getDecoder().decode("aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=");

        var secretParam = FormattedLabeledSecretParam.fromSecretParam(param);

        assertEquals("label_b64secret", secretParam.getLabel());
        assertArrayEquals(expectedSecretBytes, secretParam.getSecret());
    }

    @Test
    void testSecretParamWithSecretValueInPlainText() {
        final String param = "label_secret:notAllowedPlainText";

        assertThrows(IllegalArgumentException.class, () ->
            FormattedLabeledSecretParam.fromSecretParam(param)
        );
    }

    @Test
    void testPasswordParam() {
        final String param = "passwordlabel:myPlainTextPassword";

        var pwParam = FormattedLabeledSecretParam.fromPasswordParam(param);

        assertEquals("passwordlabel", pwParam.getLabel());
        assertArrayEquals("myPlainTextPassword".toCharArray(), pwParam.getPassword());
    }

    @Test
    void testb64PasswordParam() {
        final String param = "mysecret:base64," + Base64.getEncoder()
            .encodeToString("topSecret!".getBytes(StandardCharsets.UTF_8));

        var pwParam = FormattedLabeledSecretParam.fromPasswordParam(param);
        assertEquals("mysecret", pwParam.getLabel());
        assertArrayEquals("topSecret!".toCharArray(), pwParam.getPassword());
    }

}
