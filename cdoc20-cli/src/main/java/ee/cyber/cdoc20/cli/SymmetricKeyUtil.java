package ee.cyber.cdoc20.cli;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc20.CDocValidationException;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyMaterial;

/**
 * Symmetric key usage in CDOC is supported by CDOC format, but its use cases are not finalized.
 * In the future, symmetric key may be derived using password-based key-derivation algorithm or from hardware token.
 * For now, symmetric key can be provided directly from the command line (or from a file with @option)
 */
public final class SymmetricKeyUtil {

    public static final String BASE_64_PREFIX = "base64,";

    private static final String SYMMETRIC_KEY_DESCRIPTION = "symmetric key with label. "
        + "Must have format";
    private static final String SYMMETRIC_KEY_FORMAT_DETAILS = "can be plain text or base64 "
        + "encoded binary. In case of base64, it must be prefixed with `base64,`";

    // --secret format description, used in cdoc <cmd> classes
    public static final String SECRET_DESCRIPTION = SYMMETRIC_KEY_DESCRIPTION
        + " <label>:<secret>. <secret> " + SYMMETRIC_KEY_FORMAT_DETAILS;

    // --password format description, used in cdoc <cmd> classes
    public static final String PASSWORD_DESCRIPTION = SYMMETRIC_KEY_DESCRIPTION
        + " <label>:<password>. <password> " + SYMMETRIC_KEY_FORMAT_DETAILS;

    private SymmetricKeyUtil() { }

    private static final Logger log = LoggerFactory.getLogger(SymmetricKeyUtil.class);

    public static List<EncryptionKeyMaterial> extractEncryptionKeyMaterialFromSecrets(
        String[] secrets
    ) throws CDocValidationException {
        if (secrets == null || secrets.length == 0) {
            return List.of();
        }

        List<EncryptionKeyMaterial> result = new LinkedList<>();

        for (String secret: secrets) {
            var entry = extractKeyMaterialFromSecret(secret);
            EncryptionKeyMaterial km = EncryptionKeyMaterial.from(entry.getKey(), entry.getValue());
            result.add(km);
        }
        return result;
    }

    public static EncryptionKeyMaterial extractEncryptionKeyMaterialFromPassword(
        String password
    ) throws GeneralSecurityException, CDocValidationException {
        var entry = extractKeyMaterialFromPassword(password);
        return EncryptionKeyMaterial.from(entry.getKey(), entry.getValue());
    }

    /**
     * Extract symmetric key material from formatted secret  "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedSecret formatted as label:secret where secret can be base64 encoded bytes or
     *                        regular utf-8 string. Base64 encoded string must be prefixed with
     *                        'base64,', followed by base64 string
     * @return DecryptionKeyMaterial created from formattedSecret
     * @throws CDocValidationException if formattedSecret is not in format specified
     * @throws IllegalArgumentException if base64 secret cannot be decoded
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterial(String formattedSecret)
            throws CDocValidationException {

        var entry = extractKeyMaterialFromSecret(formattedSecret);
        return DecryptionKeyMaterial.fromSecretKey(entry.getValue(), entry.getKey());
    }

    /**
     * Extract symmetric key material from formatted password "label:Password123!" or "label:base64,
     * UGFzc3dvcmQxMjMh".
     * @param formattedPassword formatted as label:password where password can be base64 encoded
     *                          bytes or regular utf-8 string. Base64 encoded string must be
     *                          prefixed with 'base64,', followed by base64 string
     * @return DecryptionKeyMaterial created from password
     * @throws GeneralSecurityException if key extraction from password has failed
     * @throws CDocValidationException if password is not in format specified
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterialFromPassword(
        String formattedPassword
    ) throws GeneralSecurityException, CDocValidationException {
        var entry = extractKeyMaterialFromPassword(formattedPassword);

        return DecryptionKeyMaterial.fromSecretKey(entry.getValue(), entry.getKey());
    }

    /**
     * Extract symmetric key material from formatted secret "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedSecret formatted as label:secret where secret can be base64 encoded bytes
     *                        or regular utf-8 string. Base64 encoded string must be prefixed with
     *                        'base64,', followed by base64 string
     * @return AbstractMap.SimpleEntry<SecretKey, String> with extracted SecretKey and label
     * @throws CDocValidationException if formattedSecret is not in format specified
     * @throws IllegalArgumentException if base64 secret cannot be decoded
     */
    private static AbstractMap.SimpleEntry<SecretKey, String> extractKeyMaterialFromSecret(
        String formattedSecret
    ) throws CDocValidationException {
        var entry = splitPasswordAndLabel(formattedSecret, "secret");
        SecretKey key = new SecretKeySpec(entry.getKey(), "");
        return new AbstractMap.SimpleEntry<>(key, entry.getValue());
    }

    /**
     * Extract symmetric key material from formatted password "label:Password123!" or "label:base64,
     * UGFzc3dvcmQxMjMh"
     * @param formattedPassword formatted as label:password where password can be base64 encoded
     *                          bytes or regular utf-8 string. Base64 encoded string must be
     *                          prefixed with 'base64,', followed by base64 string
     * @return SecretKey with derived key from password
     * @throws GeneralSecurityException if key extraction from password has failed
     * @throws CDocValidationException if password is not in format specified
     */
    private static AbstractMap.SimpleEntry<SecretKey, String> extractKeyMaterialFromPassword(
        String formattedPassword
    ) throws CDocValidationException, GeneralSecurityException {

        var entry = splitPasswordAndLabel(formattedPassword, "password");
        SecretKey key = Crypto.deriveKekFromPassword(entry.getKey());
        return new AbstractMap.SimpleEntry<>(key, entry.getValue());
    }

    private static AbstractMap.SimpleEntry<byte[], String> splitPasswordAndLabel(
        String formattedOption,
        String optionName
    ) throws CDocValidationException {
        var parts = formattedOption.split(":");

        if (parts.length != 2) {
            throw new CDocValidationException(
                String.format("%s must have format label:%s", optionName, optionName)
            );
        }

        String label = parts[0];
        String password = parts[1];

        byte[] optionBytes;

        if (password.startsWith(BASE_64_PREFIX)) {
            optionBytes = Base64.getDecoder().decode(password.substring(BASE_64_PREFIX.length()));
            log.debug("Decoded {} bytes from {} (base64)", optionBytes.length, optionName);
        } else {
            optionBytes = password.getBytes(StandardCharsets.UTF_8);
            log.debug("Decoded {} bytes from {}", optionBytes.length, optionName);
        }
        log.info("Label for symmetric key: {}", label);

        return new AbstractMap.SimpleEntry<>(optionBytes, label);
    }
}
