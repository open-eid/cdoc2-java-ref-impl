package ee.cyber.cdoc20.client;

import ee.cyber.cdoc20.client.model.Capsule;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.Optional;

public class EcCapsuleClientImpl implements EcCapsuleClient {
    private static final Logger log = LoggerFactory.getLogger(EcCapsuleClientImpl.class);

    private final KeyCapsuleClient keyCapsulesClient;

    public EcCapsuleClientImpl(KeyCapsuleClient keyCapsulesClient) {
        this.keyCapsulesClient = keyCapsulesClient;
    }

    @Override
    public String storeSenderKey(ECPublicKey receiverKey, ECPublicKey senderKey) throws ExtApiException {

        EllipticCurve curve;
        try {
            curve = EllipticCurve.forPubKey(receiverKey);
            EllipticCurve senderCurve = EllipticCurve.forPubKey(senderKey);

            if (curve != senderCurve) {
                throw new IllegalArgumentException("receiverKey and senderKey curves do not match");
            }
        } catch (GeneralSecurityException gse) {
            log.error(gse.toString(), gse);
            throw new ExtApiException(gse);
        }

        if (EllipticCurve.secp384r1 != curve) {
            // API doesn't support other curves beside secp384r1
            throw new IllegalArgumentException("Unsupported EC curve " + curve);
        }

        Capsule capsule = new Capsule()
                .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1)
                .recipientId(ECKeys.encodeEcPubKeyForTls(curve, receiverKey))
                .ephemeralKeyMaterial(ECKeys.encodeEcPubKeyForTls(curve, senderKey));

        return keyCapsulesClient.storeCapsule(capsule);
    }

    @Override
    public Optional<ECPublicKey> getSenderKey(String transactionId) throws ExtApiException {

        try {
            Optional<Capsule> capsuleOptional = keyCapsulesClient.getCapsule(transactionId);
            if (capsuleOptional.isPresent()) {
                Capsule capsule = capsuleOptional.get();

                if (Capsule.CapsuleTypeEnum.ECC_SECP384R1 != capsule.getCapsuleType()) {
                    throw new ExtApiException("Unsupported capsule type " + capsule.getCapsuleType());
                }

                return Optional.of(
                    EllipticCurve.secp384r1.decodeFromTls(ByteBuffer.wrap(capsule.getEphemeralKeyMaterial()))
                );
            }

            return Optional.empty();

        } catch (GeneralSecurityException gse) {
            log.error("Error decoding key server response", gse);
            throw new ExtApiException(gse);
        }
    }

    @Override
    public String getServerIdentifier() {
        return keyCapsulesClient.getServerIdentifier();
    }
}
