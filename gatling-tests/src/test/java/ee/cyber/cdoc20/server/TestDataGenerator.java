package ee.cyber.cdoc20.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.cyber.cdoc20.server.conf.LoadedKeyStore;
import ee.cyber.cdoc20.server.conf.TestConfig;
import ee.cyber.cdoc20.server.datagen.CertUtil;
import ee.cyber.cdoc20.server.dto.GeneratedCapsule;
import ee.cyber.cdoc20.server.dto.KeyCapsuleRequest;
import ee.cyber.cdoc20.server.dto.KeyCapsuleType;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
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

    public GeneratedCapsule generateCapsule(Long userId) {
        log.debug("generateCapsule(userId={})", userId);

        var keyStore = this.getClientKeyStore(userId);
        // ephemeral key pair
        var senderKeyPair = CertUtil.generateEcKeyPair();
        var request = createEccKeyCapsuleRequest(keyStore, senderKeyPair);

        return new GeneratedCapsule(keyStore, senderKeyPair, request);
    }

    public GeneratedCapsule generateCapsuleWithWrongRecipient(Long userId) {
        log.debug("generateCapsuleWithWrongRecipient(userId={})", userId);

        var currentUserKeyStore = this.getClientKeyStore(userId);
        var otherUserKeyStore = this.getClientKeyStore(userId + 1L);

        if (currentUserKeyStore.getPublicKey().equals(otherUserKeyStore.getPublicKey())) {
            throw new IllegalArgumentException(
                String.format(
                    "Invalid test data detected: key stores %s and %s contain the same keys",
                    currentUserKeyStore.getFile().getAbsolutePath(),
                    otherUserKeyStore.getFile().getAbsoluteFile()
                )
            );
        }

        var senderKeyPair = CertUtil.generateEcKeyPair();
        var request = createEccKeyCapsuleRequest(otherUserKeyStore, senderKeyPair);
        return new GeneratedCapsule(otherUserKeyStore, senderKeyPair, request);
    }

    /**
     * @param userId the userId given by Gatling (starts from 1, increasing)
     * @return n-th keystore from configuration
     */
    public LoadedKeyStore getClientKeyStore(long userId) {
        var keyStores = this.conf.getKeyStores();

        // use modulo in case the test uses more users than there are key stores
        int index = (int) userId % keyStores.size();

        return keyStores.get(index);
    }

    private static KeyCapsuleRequest createEccKeyCapsuleRequest(LoadedKeyStore recipient, KeyPair sender) {
        return new KeyCapsuleRequest(
            CertUtil.encodePublicKey(recipient.getPublicKey()),
            CertUtil.encodePublicKey((ECPublicKey) sender.getPublic()),
            KeyCapsuleType.ecc_secp384r1
        );
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
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes).substring(0, length);
    }
}
