package ee.cyber.cdoc2.cli.util;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSymmetricKeyLabelParams;


/**
 * Allows to enter label and secret in following format:
 * labelForBase64EncodedSecret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=
 * or
 * labelForClearTextPassword:mySecretPassword!
 * <p>
 * where first part before ':' is label and second part after ':' is secret. Secret part can be base64
 * encoded, then its prefixed with "base64,"
 * <p>
 * Clear text password is only allowed for password. When password is base64 encoded, then encoded
 * bytes are from UTF8 charset.
 */
class FormattedLabeledSecretParam implements LabeledPassword, LabeledSecret {
    public static final String BASE_64_PREFIX = "base64,";

    private static final Logger log = LoggerFactory.getLogger(FormattedLabeledSecretParam.class);

    private final EncryptionKeyOrigin keyOrigin;

    private final String label;

    private final byte[] secretAsBytes;

    private final char[] secretAsPassword;

    FormattedLabeledSecretParam(EncryptionKeyOrigin keyOrigin, ParsedFields parsed) {
        this.keyOrigin = keyOrigin;
        this.label = parsed.label();
        this.secretAsBytes = parsed.secret();
        this.secretAsPassword = parsed.pw();
    }

    /**
     * Parse LabeledPassword from formatted String <label_part>:<secret_part>.
     * Secret part is prefixed with "base64," and the value is Base64 encoded
     * Example: label123:base64,cGFzc3dvcmQ=
     * */
    public static LabeledSecret fromSecretParam(String formattedSecret) {
        final EncryptionKeyOrigin secretOrigin = EncryptionKeyOrigin.SECRET;
        var parsed = parseFields(formattedSecret, secretOrigin);
        return new FormattedLabeledSecretParam(secretOrigin, parsed);
    }

    /**
     * Parse LabeledPassword from formatted String <label_part>:<password_part>.
     * Password part can be base64 encoded, then base64 part is prefixed with "base64,"
     * Example: label123:password or label123:base64,cGFzc3dvcmQ=
     * When password is base64 encoded, then decoded byte are converted into Java String using utf8 encoding.
     * */
    public static LabeledPassword fromPasswordParam(String formattedPassword) {
        final EncryptionKeyOrigin passwordOrigin = EncryptionKeyOrigin.PASSWORD;
        var parsed = parseFields(formattedPassword, passwordOrigin);
        return new FormattedLabeledSecretParam(passwordOrigin, parsed);
    }

    private static ParsedFields parseFields(
        String formattedSecret,
        EncryptionKeyOrigin keyOrigin
    ) {
        var parts = formattedSecret.split(":");
        String optionName = keyOrigin.name();
        if (parts.length != 2) {
            throw new IllegalArgumentException(
                String.format("Option %s must have format label:value", optionName)
            );
        }

        String secret = parts[1];

        if (secret.startsWith(BASE_64_PREFIX)) {
            byte[] secretAsBytes = Base64.getDecoder().decode(secret.substring(BASE_64_PREFIX.length()));

            log.debug("Decoded bytes from base64 with length {}", secretAsBytes.length);

            CharBuffer chBuf = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(secretAsBytes));
            char[] secretAsPassword = new char[chBuf.remaining()];
            chBuf.get(secretAsPassword);

            return new ParsedFields(parts[0], secretAsBytes, secretAsPassword);
        } else {
            if (keyOrigin == EncryptionKeyOrigin.SECRET) {
                throw new IllegalArgumentException("Secret must be as a base64 encoded value");
            }

            char[] secretAsPassword = secret.toCharArray();
            byte[] secretAsBytes = secret.getBytes(StandardCharsets.UTF_8);

            return new ParsedFields(parts[0], secretAsBytes, secretAsPassword);
        }
    }

    public EncryptionKeyOrigin getOrigin() {
        return keyOrigin;
    }

    public String getLabel() {
        return label;
    }

    @Override
    public KeyLabelParams getKeyLabelParams() {
        return createSymmetricKeyLabelParams(this.keyOrigin, this.label);
    }

    public byte[] getSecret() {
        return Arrays.copyOf(secretAsBytes, secretAsBytes.length);
    }

    public char[] getPassword() {
        return Arrays.copyOf(secretAsPassword, secretAsPassword.length);
    }

    private record ParsedFields(String label, byte[] secret, char[] pw) {
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) return false;
            ParsedFields that = (ParsedFields) o;
            return Objects.deepEquals(this.pw, that.pw)
                && Objects.equals(this.label, that.label)
                && Objects.deepEquals(this.secret, that.secret);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.label, Arrays.hashCode(this.secret), Arrays.hashCode(this.pw));
        }

        @Override
        public String toString() {
            return "ParsedFields{"
                + "label='" + this.label + '\''
                + ", secret=*****"
                + ", pw=*****"
                + '}';
        }
    }

}
