package ee.cyber.cdoc20.cli;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc20.CDocValidationException;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyMaterial;

/**
 * Symmetric key usage in CDOC is supported by CDOC format, but its use cases are not finalized.
 * In the future, symmetric key may be derived using password-based key-derivation algorithm or from hardware token.
 * For now, symmetric key can be provided directly from the command line (or from a file with @option)
 */
public final class SymmetricKeyUtil {

    public static final String BASE_64_PREFIX = "base64,";

    // --secret format description, used in cdoc <cmd> classes
    public static final String SECRET_DESCRIPTION = "symmetric key with label. Must have format <label>:<secret>. "
            + "<secret> can be plain text or base64 encoded binary, in case of base64, "
            + "it must be prefixed with `base64,`";

    private SymmetricKeyUtil() { }

    private static final Logger log = LoggerFactory.getLogger(SymmetricKeyUtil.class);

    public static List<EncryptionKeyMaterial> extractEncryptionKeyMaterial(String[] secrets)
            throws CDocValidationException {
        if (secrets == null || secrets.length == 0) {
            return List.of();
        }

        List<EncryptionKeyMaterial> result = new LinkedList<>();

        for (String secret: secrets) {
            var entry = extractEncryptionKeyMaterial(secret);
            EncryptionKeyMaterial km = EncryptionKeyMaterial.from(entry.getKey(), entry.getValue());
            result.add(km);
        }
        return result;
    }

    /**
     * Extract symmetric key material from formatted secret  "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedSecret formatted as label:secret where secret can be base64 encoded bytes or regular utf-8 string
     *                        Base64 encoded string must be prefixed with 'base64,', followed by base64 string
     * @return DecryptionKeyMaterial created from formattedSecret
     * @throws CDocValidationException if formattedSecret is not in format specified
     * @throws IllegalArgumentException if base64 secret cannot be decoded
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterial(String formattedSecret)
            throws CDocValidationException {

        var entry = extractEncryptionKeyMaterial(formattedSecret);
        return DecryptionKeyMaterial.fromSecretKey(entry.getValue(), entry.getKey());
    }

    /**
     * Extract symmetric key material from formatted secret "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedSecret formatted as label:secret where secret can be base64 encoded bytes or regular utf-8 string
     *                        Base64 encoded string must be prefixed with 'base64,', followed by base64 string
     * @return AbstractMap.SimpleEntry<SecretKey, String> with extracted SecretKey and label
     * @throws CDocValidationException if formattedSecret is not in format specified
     * @throws IllegalArgumentException if base64 secret cannot be decoded
     */
    private static AbstractMap.SimpleEntry<SecretKey, String> extractEncryptionKeyMaterial(String formattedSecret)
            throws CDocValidationException {

        var parts = formattedSecret.split(":");

        if (parts.length != 2) {
            throw new CDocValidationException("Secret must have format label:secret");
        }

        String label = parts[0];
        String secret = parts[1];

        byte[] secretBytes;

        if (secret.startsWith(BASE_64_PREFIX)) {
            secretBytes = Base64.getDecoder().decode(secret.substring(BASE_64_PREFIX.length()));
            log.debug("Decoded {} bytes from secret (base64)", secretBytes.length);
        } else {
            secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            log.debug("Decoded {} bytes from secret", secretBytes.length);
        }

        log.info("Label for symmetric key: {}", label);
        SecretKey key = new SecretKeySpec(secretBytes, "");
        return new AbstractMap.SimpleEntry<>(key, label);
    }
}
