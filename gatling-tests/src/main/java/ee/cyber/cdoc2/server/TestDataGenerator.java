package ee.cyber.cdoc2.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.cyber.cdoc2.server.conf.LoadedKeyStore;
import ee.cyber.cdoc2.server.conf.TestConfig;
import ee.cyber.cdoc2.server.dto.KeyCapsuleRequest;
import ee.cyber.cdoc2.server.dto.KeyCapsuleType;
import ee.cyber.cdoc2.server.datagen.CertUtil;
import ee.cyber.cdoc2.server.dto.GeneratedCapsule;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Random;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

/**
 * Generates test data
 */
@Slf4j
@RequiredArgsConstructor
public class TestDataGenerator {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Random RANDOM = new Random();

    private final TestConfig conf;

    public GeneratedCapsule generateEccCapsule(Long userId) {
        log.debug("generateEccCapsule(userId={})", userId);

        var keyStore = this.getEccKeyStore(userId);
        // ephemeral key pair
        var senderKeyPair = CertUtil.generateEcKeyPair();

        return new GeneratedCapsule(
            keyStore, createEccKeyCapsuleRequest(keyStore, senderKeyPair)
        );
    }

    public GeneratedCapsule generateRsaCapsule(Long userId) {
        log.debug("generateRsaCapsule(userId={})", userId);

        var keyStore = this.getRsaKeyStore(userId);
        return new GeneratedCapsule(keyStore, createRsaKeyCapsuleRequest(keyStore));
    }

    public GeneratedCapsule generateEccCapsuleWithWrongRecipient(Long userId) {
        log.debug("generateEccCapsuleWithWrongRecipient(userId={})", userId);

        var currentUserKeyStore = this.getEccKeyStore(userId);
        var otherUserKeyStore = this.getEccKeyStore(userId + 1L);

        if (currentUserKeyStore.publicKey().equals(otherUserKeyStore.publicKey())) {
            throw new IllegalArgumentException(
                String.format(
                    "Invalid test data detected: key stores %s and %s contain the same keys",
                    currentUserKeyStore.file().getAbsolutePath(),
                    otherUserKeyStore.file().getAbsoluteFile()
                )
            );
        }

        var senderKeyPair = CertUtil.generateEcKeyPair();
        var request = createEccKeyCapsuleRequest(otherUserKeyStore, senderKeyPair);
        return new GeneratedCapsule(otherUserKeyStore, request);
    }

    public GeneratedCapsule generateRsaCapsuleWithWrongRecipient(Long userId) {
        log.debug("generateRsaCapsuleWithWrongRecipient(userId={})", userId);

        var currentUserKeyStore = this.getRsaKeyStore(userId);
        var otherUserKeyStore = this.getRsaKeyStore(userId + 1L);

        if (currentUserKeyStore.publicKey().equals(otherUserKeyStore.publicKey())) {
            throw new IllegalArgumentException(
                String.format(
                    "Invalid test data detected: key stores %s and %s contain the same keys",
                    currentUserKeyStore.file().getAbsolutePath(),
                    otherUserKeyStore.file().getAbsoluteFile()
                )
            );
        }
        return new GeneratedCapsule(otherUserKeyStore, createRsaKeyCapsuleRequest(otherUserKeyStore));
    }

    /**
     * @param userId the userId given by Gatling (starts from 1, increasing)
     * @return n-th elliptic curve keystore from configuration
     */
    public LoadedKeyStore getEccKeyStore(long userId) {
        var keyStores = this.conf.getEccKeyStores();

        // use modulo in case the test uses more users than there are key stores
        int index = (int) userId % keyStores.size();

        return keyStores.get(index);
    }

    /**
     * @param userId the userId given by Gatling (starts from 1, increasing)
     * @return n-th RSA keystore from configuration
     */
    public LoadedKeyStore getRsaKeyStore(long userId) {
        var keyStores = this.conf.getRsaKeyStores();

        if (keyStores.isEmpty()) {
            throw new IllegalStateException("No RSA key stores configured");
        }

        // use modulo in case the test uses more users than there are key stores
        int index = (int) userId % keyStores.size();

        return keyStores.get(index);
    }

    /**
     * @return an elliptic curve keystore from configuration
     */
    public LoadedKeyStore getRandomEccKeyStore() {
        return getEccKeyStore(1L);
    }

    /**
     * @return a RSA keystore from configuration
     */
    public LoadedKeyStore getRandomRsaKeyStore() {
        return getRsaKeyStore(1L);
    }

    public static KeyCapsuleRequest createEccKeyCapsuleRequest(LoadedKeyStore recipient, KeyPair sender) {
        if (recipient.publicKey() instanceof ECPublicKey ecPublicKey) {
            return new KeyCapsuleRequest(
                CertUtil.encodePublicKey(ecPublicKey),
                CertUtil.encodePublicKey((ECPublicKey) sender.getPublic()),
                KeyCapsuleType.ECC_SECP384R1
            );
        } else {
            throw new IllegalArgumentException(
                "Expecting key store with EcPublicKey, got " + recipient.publicKey().getClass()
            );
        }
    }

    public static KeyCapsuleRequest createRsaKeyCapsuleRequest(LoadedKeyStore recipient) {
        return createRsaKeyCapsuleRequest(
            recipient,
            recipient.publicKey().getEncoded() // in reality, should be encrypted kek
        );
    }

    public static KeyCapsuleRequest createRsaKeyCapsuleRequest(LoadedKeyStore recipient,
                                                               byte[] keyMaterial) {
        if (recipient.publicKey() instanceof RSAPublicKey rsaPublicKey) {
            return new KeyCapsuleRequest(
                CertUtil.encodePublicKey(rsaPublicKey),
                Base64.getEncoder().encodeToString(keyMaterial),
                KeyCapsuleType.RSA
            );
        } else {
            throw new IllegalArgumentException(
                "Expecting key store with RSAPublicKey, got " + recipient.publicKey().getClass()
            );
        }
    }

    @SneakyThrows
    public static String toJson(Object dto) {
        return JSON.writeValueAsString(dto);
    }

    /**
     * Generates a random string
     * @param length the length of the string
     * @return a random string with the given length
     */
    public static String randomString(int length) {
        return Base64.getEncoder()
            .encodeToString(randomBytes(length))
            .substring(0, length)
            .replaceAll("/", "-"); // make url safe
    }

    /**
     * Generates random bytes
     * @param length the number of bytes to generate
     * @return random bytes
     */
    public static byte[] randomBytes(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
