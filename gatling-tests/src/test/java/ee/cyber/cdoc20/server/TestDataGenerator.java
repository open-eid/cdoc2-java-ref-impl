package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.crypto.EllipticCurve;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

import com.fasterxml.jackson.databind.ObjectMapper;

import ee.cyber.cdoc20.server.conf.LoadedKeyStore;
import ee.cyber.cdoc20.server.conf.TestConfig;
import ee.cyber.cdoc20.server.datagen.CertUtil;
import ee.cyber.cdoc20.server.dto.EccDetailsRequest;

/**
 * Generates test data
 */
@Slf4j
@RequiredArgsConstructor
public class TestDataGenerator {
    private static final ObjectMapper JSON = new ObjectMapper();

    private final TestConfig conf;

    public GeneratedCapsule generateCapsule(Long userId) {
        log.debug("generateCapsule(userId={})", userId);

        var keyStore = this.getClientKeyStore(userId);
        // ephemeral key pair
        var senderKeyPair = CertUtil.generateEcKeyPair();
        var request = createRequest(keyStore, senderKeyPair);

        return new GeneratedCapsule(keyStore, senderKeyPair, request);
    }

    public GeneratedCapsule generateCapsuleWithWrongRecipient(Long userId) {
        log.debug("generateCapsuleWithWrongRecipient(userId={})", userId);

        var currentUserKeyStore = this.getClientKeyStore(userId);
        var otherUserKeyStore = this.getClientKeyStore(userId + 1L);

        if (currentUserKeyStore.getPublicKey().equals(otherUserKeyStore.getPublicKey())) {
            throw new IllegalArgumentException(
                String.format(
                    "Invalid test data detected: keystores %s and %s contain the same keys",
                    currentUserKeyStore.getFile().getAbsolutePath(),
                    otherUserKeyStore.getFile().getAbsoluteFile()
                )
            );
        }

        var senderKeyPair = CertUtil.generateEcKeyPair();
        var request = createRequest(otherUserKeyStore, senderKeyPair);
        return new GeneratedCapsule(otherUserKeyStore, senderKeyPair, request);
    }

    /**
     * @param userId the userId given by Gatling (starts from 1, increasing)
     * @return n-th keystore from configuration
     */
    public LoadedKeyStore getClientKeyStore(long userId) {
        var keyStores = this.conf.getKeyStores();

        // use modulo in case the test uses more users than there are keystores
        int index = (int) userId % keyStores.size();

        return keyStores.get(index);
    }

    private static EccDetailsRequest createRequest(LoadedKeyStore recipient, KeyPair sender) {
        return new EccDetailsRequest(
            CertUtil.encodePublicKey(recipient.getPublicKey()),
            CertUtil.encodePublicKey((ECPublicKey) sender.getPublic()),
            (int) EllipticCurve.secp384r1.getValue()
        );
    }

    @SneakyThrows
    public static String toJson(Object dto) {
        return JSON.writeValueAsString(dto);
    }
}
