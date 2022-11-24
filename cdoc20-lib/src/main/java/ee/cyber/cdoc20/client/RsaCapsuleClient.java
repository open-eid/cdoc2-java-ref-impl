package ee.cyber.cdoc20.client;

import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

public interface RsaCapsuleClient extends ServerClient {
    String storeRsaCapsule(RSAPublicKey recipient, byte[] encryptedKek) throws ExtApiException;

    Optional<byte[]> getEncryptedKek(String transactionId) throws ExtApiException;
}
