package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.client.model.Capsule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.Optional;


@SuppressWarnings("java:S2139")
public class EcCapsuleClientImpl implements EcCapsuleClient {
    private static final Logger log = LoggerFactory.getLogger(EcCapsuleClientImpl.class);

    private final KeyCapsuleClient keyCapsulesClient;

    public EcCapsuleClientImpl(KeyCapsuleClient keyCapsulesClient) {
        this.keyCapsulesClient = keyCapsulesClient;
    }

    @Override
    public String storeSenderKey(
        ECPublicKey receiverKey,
        ECPublicKey senderKey
    ) throws ExtApiException {

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

        var capsuleType = switch (curve) {
            case SECP384R1 -> Capsule.CapsuleTypeEnum.ECC_SECP384R1;
            case SECP256R1 -> Capsule.CapsuleTypeEnum.ECC_SECP256R1;
            default -> throw new IllegalArgumentException("Unsupported EC curve " + curve);
        };

        Capsule capsule = new Capsule()
                .capsuleType(capsuleType)
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

                return switch (capsule.getCapsuleType()) {
                    case ECC_SECP384R1 -> Optional.of(
                        EllipticCurve.SECP384R1.decodeFromTls(ByteBuffer.wrap(capsule.getEphemeralKeyMaterial()))
                    );
                    case ECC_SECP256R1 -> Optional.of(
                        EllipticCurve.SECP256R1.decodeFromTls(ByteBuffer.wrap(capsule.getEphemeralKeyMaterial()))
                    );
                    default -> throw new ExtApiException("Unsupported capsule type " + capsule.getCapsuleType());
                };
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
