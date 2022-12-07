package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.client.EcCapsuleClient;
import ee.cyber.cdoc20.client.EcCapsuleClientImpl;
import ee.cyber.cdoc20.client.ExtApiException;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.client.RsaCapsuleClient;
import ee.cyber.cdoc20.client.RsaCapsuleClientImpl;
import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.recipients.EccPubKeyRecipient;
import ee.cyber.cdoc20.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc20.container.recipients.RSAPubKeyRecipient;
import ee.cyber.cdoc20.container.recipients.RSAServerKeyRecipient;
import ee.cyber.cdoc20.container.recipients.SymmetricKeyRecipient;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * Functions for deriving KEK in different scenarios
 */
public final class KekTools {

    private static final Logger log = LoggerFactory.getLogger(KekTools.class);

    private KekTools() { }


    public static byte[] deriveKekForSymmetricKey(SymmetricKeyRecipient recipient,
                                                  DecryptionKeyMaterial keyMaterial) {

        SecretKey secretKey = keyMaterial.getSecretKey().orElseThrow(
                () -> new IllegalArgumentException("Expected SecretKey for SymmetricKeyRecipient"));
        SecretKey kek = Crypto.deriveKeyEncryptionKey(recipient.getRecipientKeyLabel(),
                secretKey,
                recipient.getSalt(),
                FMKEncryptionMethod.name(recipient.getFmkEncryptionMethod()));
        return kek.getEncoded();
    }

    public static byte[] deriveKekForEcc(EccPubKeyRecipient eccPubKeyRecipient,
                                         DecryptionKeyMaterial keyMaterial)
            throws GeneralSecurityException {
        ECPublicKey senderPubKey = eccPubKeyRecipient.getSenderPubKey();

        KeyPair recipientKeyPair = keyMaterial.getKeyPair()
                .orElseThrow(() -> new IllegalArgumentException("EC key pair required for KEK derive"));

        return Crypto.deriveKeyDecryptionKey(recipientKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
    }

    public static byte[] deriveKekForEccServer(EccServerKeyRecipient keyRecipient,
                                               DecryptionKeyMaterial keyMaterial,
                                               KeyCapsuleClientFactory capsulesClientFac)
            throws GeneralSecurityException, ExtApiException, CDocParseException {

        KeyPair recipientKeyPair = keyMaterial.getKeyPair().orElseThrow(
                () -> new IllegalArgumentException("must contain EC key pair for ECC Server scenario"));

        String transactionId = keyRecipient.getTransactionId();
        if (transactionId == null) {
            log.error("No transactionId for recipient {}", keyRecipient.getRecipientKeyLabel());
            throw new CDocParseException("TransactionId missing in record");
        }

        String serverId = keyRecipient.getKeyServerId();
        if (serverId == null) {
            log.error("No serverId for recipient {}", keyRecipient.getRecipientKeyLabel());
            throw new CDocParseException("ServerId missing in record");
        }

        if (capsulesClientFac == null || capsulesClientFac.getForId(serverId) == null) {
            log.error("Configuration not found for server {}", serverId);
            throw new CDocParseException("Configuration not found for server \"" + serverId + "\"");
        }

        try {
            EcCapsuleClient client = new EcCapsuleClientImpl(capsulesClientFac.getForId(serverId));
            Optional<ECPublicKey> senderPubKeyOptional = client.getSenderKey(transactionId);
            ECPublicKey senderPubKey = senderPubKeyOptional.orElseThrow();
            return Crypto.deriveKeyDecryptionKey(recipientKeyPair, senderPubKey, Crypto.KEK_LEN_BYTES);
        } catch (NoSuchElementException nse) {
            log.error("Key not found for id {} from {}", transactionId, serverId);
            throw new ExtApiException("Sender key not found for " + transactionId);
        } catch (ExtApiException apiException) {
            log.error("Error querying {} for {} ({})", serverId, transactionId, apiException);
            throw apiException;
        }

    }

    public static byte[] deriveKekForRsaServer(RSAServerKeyRecipient recipient,
                                               DecryptionKeyMaterial keyMaterial,
                                               KeyCapsuleClientFactory capsulesClientFac)
            throws GeneralSecurityException, ExtApiException, CDocParseException {

        String transactionId = recipient.getTransactionId();
        String serverId = recipient.getKeyServerId();

        KeyPair recipientKeyPair = keyMaterial.getKeyPair().orElseThrow(
                () -> new IllegalArgumentException("must contain RSA key pair for RSA Server scenario"));

        if (!"RSA".equals(recipientKeyPair.getPrivate().getAlgorithm())) {
            throw new IllegalArgumentException("must contain RSA key pair for RSA scenario");
        }

        if (transactionId == null) {
            log.error("No transactionId for recipient {}", recipient.getRecipientKeyLabel());
            throw new CDocParseException("TransactionId missing in record");
        }

        if (serverId == null) {
            log.error("No serverId for recipient {}", recipient.getRecipientKeyLabel());
            throw new CDocParseException("ServerId missing in record");
        }

        if (capsulesClientFac == null || capsulesClientFac.getForId(serverId) == null) {
            log.error("Configuration not found for server {}", serverId);
            throw new CDocParseException("Configuration not found for server \"" + serverId + "\"");
        }

        RsaCapsuleClient client = new RsaCapsuleClientImpl(capsulesClientFac.getForId(serverId));
        byte[] encryptedKek = client.getEncryptedKek(transactionId).orElseThrow();

        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) recipientKeyPair.getPrivate();
        return RsaUtils.rsaDecrypt(encryptedKek, rsaPrivateKey);

    }

    public static byte[] deriveKekForRsa(RSAPubKeyRecipient rsaPubKeyRecipient, DecryptionKeyMaterial keyMaterial)
        throws GeneralSecurityException {

        KeyPair recipientKeyPair = keyMaterial.getKeyPair().orElseThrow(
                () -> new IllegalArgumentException("must contain RSA key pair for RSA scenario"));

        if (!"RSA".equals(recipientKeyPair.getPrivate().getAlgorithm())) {
            throw new IllegalArgumentException("must contain RSA key pair for RSA scenario");
        }

        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) recipientKeyPair.getPrivate();
        return RsaUtils.rsaDecrypt(rsaPubKeyRecipient.getEncryptedKek(), rsaPrivateKey);
    }
}
