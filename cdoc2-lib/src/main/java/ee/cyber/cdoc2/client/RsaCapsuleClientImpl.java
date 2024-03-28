package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.crypto.RsaUtils;
import ee.cyber.cdoc2.client.model.Capsule;

import java.security.interfaces.RSAPublicKey;
import java.util.Optional;


public class RsaCapsuleClientImpl implements RsaCapsuleClient {
    final KeyCapsuleClient keyCapsulesClient;

    public RsaCapsuleClientImpl(KeyCapsuleClient serverClient) {
        keyCapsulesClient = serverClient;
    }

    @Override
    public String storeRsaCapsule(RSAPublicKey recipient, byte[] encryptedKek) throws ExtApiException {
        Capsule capsule = new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.RSA)
            .recipientId(RsaUtils.encodeRsaPubKey(recipient))
            .ephemeralKeyMaterial(encryptedKek);

        return keyCapsulesClient.storeCapsule(capsule);
    }

    @Override
    public Optional<byte[]> getEncryptedKek(String transactionId) throws ExtApiException {

        Optional<Capsule> capsuleOpt = keyCapsulesClient.getCapsule(transactionId);
        if (capsuleOpt.isPresent()) {
            Capsule capsule = capsuleOpt.get();
            if (capsule.getCapsuleType() != Capsule.CapsuleTypeEnum.RSA) {
                throw new ExtApiException("Invalid capsule type " + capsule.getCapsuleType());
            }

            return Optional.of(capsule.getEphemeralKeyMaterial());
        }

        return Optional.empty();
    }

    @Override
    public String getServerIdentifier() {
        return keyCapsulesClient.getServerIdentifier();
    }
}
