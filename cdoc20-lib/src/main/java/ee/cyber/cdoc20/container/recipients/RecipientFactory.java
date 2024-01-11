package ee.cyber.cdoc20.container.recipients;

import ee.cyber.cdoc20.client.EcCapsuleClient;
import ee.cyber.cdoc20.client.EcCapsuleClientImpl;
import ee.cyber.cdoc20.client.ExtApiException;
import ee.cyber.cdoc20.client.KeyCapsuleClient;
import ee.cyber.cdoc20.client.RsaCapsuleClient;
import ee.cyber.cdoc20.client.RsaCapsuleClientImpl;
import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import ee.cyber.cdoc20.crypto.EncryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc20.crypto.RsaUtils;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc20.fbs.recipients.PBKDF2Capsule;
import ee.cyber.cdoc20.fbs.recipients.SymmetricKeyCapsule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Factory to create Recipients from different cryptographic keys
 */
public final class RecipientFactory {

    private static final Logger log = LoggerFactory.getLogger(RecipientFactory.class);
    private static final String INVALID_FMK_LEN = "Invalid FMK len";

    private RecipientFactory() { }

    /**
     * Build recipients. For each recipient KEK (key encryption key) key is derived from recipients key material and fmk
     * is encrypted with KEK.
     * @param fmk file master key generated per CDOC2 envelope
     * @param recipientKeys recipients key material used to derive KEK
     * @param serverClient if server client is provided, then key material for deriving KEK or encrypted KEK is stored
     *                     in key server
     * @return Recipients list created from provided key material
     * @throws GeneralSecurityException
     * @throws ExtApiException if communication with key server failed
     */
    public static Recipient[] buildRecipients(byte[] fmk, List<EncryptionKeyMaterial> recipientKeys,
                                              @Nullable KeyCapsuleClient serverClient)
            throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientKeys);
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException(INVALID_FMK_LEN);
        }

        if (recipientKeys.isEmpty()) {
            throw new IllegalArgumentException("At least one recipient required");
        }

        List<Recipient> result = new ArrayList<>(recipientKeys.size());
        for (EncryptionKeyMaterial encKeyMaterial : recipientKeys) {
            Key key = encKeyMaterial.getKey();
            String keyLabel = encKeyMaterial.getLabel();

            if (key instanceof RSAPublicKey rsaPublicKey) {
                if (serverClient != null) {
                    RsaCapsuleClient rsaCapsuleClient = new RsaCapsuleClientImpl(serverClient);
                    result.add(buildRsaServerKeyRecipient(fmk, rsaPublicKey, keyLabel, rsaCapsuleClient));
                } else {
                    result.add(buildRsaRecipient(fmk, rsaPublicKey, keyLabel));
                }

            } else if (key instanceof ECPublicKey ecPublicKey) {
                if (serverClient != null) {
                    result.add(buildEccServerKeyRecipient(fmk, ecPublicKey, keyLabel,
                            new EcCapsuleClientImpl(serverClient)));
                } else {
                    result.add(buildEccRecipient(fmk, ecPublicKey, keyLabel));
                }
            } else if (key instanceof SecretKey preSharedKey) {
                if (serverClient != null) {
                    log.info("For symmetric key scenario, key server will not be used.");
                }
                checkKeyTypeAndBuildRecipient(
                    result, fmk, preSharedKey, keyLabel, encKeyMaterial.getKeyOrigin()
                );
            } else {
                throw new InvalidKeyException("Unsupported key algorithm " + key.getAlgorithm());
            }
        }

        return result.toArray(new Recipient[0]);
    }

    private static void checkKeyTypeAndBuildRecipient(
        List<Recipient> recipients,
        byte[] fmk,
        SecretKey preSharedKey,
        String keyLabel,
        EncryptionKeyOrigin keyType
    ) throws GeneralSecurityException {
        if (EncryptionKeyOrigin.FROM_PASSWORD.equals(keyType)) {
            recipients.add(buildPBKDF2Recipient(fmk,  preSharedKey, keyLabel,
                FMKEncryptionMethod.name(Envelope.FMK_ENC_METHOD_BYTE)));
        } else {
            recipients.add(buildSymmetricKeyRecipient(fmk,  preSharedKey, keyLabel,
                FMKEncryptionMethod.name(Envelope.FMK_ENC_METHOD_BYTE)));
        }
    }

    /**
     * Fill RSAPubKeyRecipient with data, so that it is ready to be serialized into CDOC header.
     * @param fmk file master key (plain)
     * @param recipientPubRsaKey  recipients public RSA key
     * @param keyLabel recipientPubRsaKey description
     * @throws GeneralSecurityException if kek encryption with recipientPubRsaKey fails
     */
    static RSAPubKeyRecipient buildRsaRecipient(byte[] fmk, RSAPublicKey recipientPubRsaKey, String keyLabel)
            throws GeneralSecurityException {

        Objects.requireNonNull(recipientPubRsaKey);
        Objects.requireNonNull(fmk);
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Illegal FMK length " + fmk.length);
        }

        byte[] kek = new byte[Crypto.FMK_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(kek);

        byte[] encryptedKek = RsaUtils.rsaEncrypt(kek, recipientPubRsaKey);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        return new RSAPubKeyRecipient(recipientPubRsaKey, encryptedKek, encryptedFmk, keyLabel);
    }

    /**
     * Generate sender key pair for the recipient. Encrypt fmk with KEK derived from generated sender private key
     * and recipient public key
     * @param fmk file master key (plain)
     * @param recipientPubKey  recipient public keys
     * @return EccRecipient with generated sender and recipient public key and
     *          fmk encrypted with sender private and recipient public key
     * @throws InvalidKeyException if recipient key is not suitable
     * @throws GeneralSecurityException if other crypto related exceptions happen
     */
    static EccPubKeyRecipient buildEccRecipient(byte[] fmk, ECPublicKey recipientPubKey, String keyLabel)
            throws GeneralSecurityException {

        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(fmk);
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Illegal FMK length " + fmk.length);
        }

        EllipticCurve curve;
        try {
            curve = EllipticCurve.forPubKey(recipientPubKey);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException
                | NoSuchProviderException generalSecurityException) {
            throw new InvalidKeyException(generalSecurityException);
        }

        try {
            if (!curve.isValidKey(recipientPubKey)) {
                throw new InvalidKeyException("ECKey not valid");
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException("ECKey not valid");
        }

        KeyPair senderEcKeyPair = curve.generateEcKeyPair();
        byte[] kek = Crypto.deriveKeyEncryptionKey(senderEcKeyPair, recipientPubKey, Crypto.KEK_LEN_BYTES);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        return new EccPubKeyRecipient(
            curve, recipientPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk, keyLabel
        );
    }

    /**
     * Fill EccServerKeyRecipient POJO, so that they are ready to be serialized into CDOC header. Calls
     * {@link #buildEccRecipient(byte[], ECPublicKey, String)} to generate sender key pair and encrypt FMK.
     * Stores sender public key in key server and gets corresponding transactionId from server.
     * @param fmk file master key (plain)
     * @param recipientPubKey  list of recipients public keys
     * @param serverClient used to store sender public key and get transactionId
     * @return For each recipient create EccServerKeyRecipient with fields filled
     */
    static EccServerKeyRecipient buildEccServerKeyRecipient(byte[] fmk, ECPublicKey recipientPubKey,
            String keyLabel, EcCapsuleClient serverClient) throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(serverClient);
        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException(INVALID_FMK_LEN);
        }

        EccPubKeyRecipient eccPubKeyRecipient = buildEccRecipient(fmk, recipientPubKey, keyLabel);

        String transactionId = serverClient.storeSenderKey(
            eccPubKeyRecipient.getRecipientPubKey(), eccPubKeyRecipient.getSenderPubKey()
        );
        String serverId = serverClient.getServerIdentifier();

        return new EccServerKeyRecipient(eccPubKeyRecipient.getEllipticCurve(),
                eccPubKeyRecipient.getRecipientPubKey(), serverId, transactionId,
                eccPubKeyRecipient.getEncryptedFileMasterKey(), keyLabel);
    }

    static RSAServerKeyRecipient buildRsaServerKeyRecipient(byte[] fmk, RSAPublicKey recipientPubKey,
                                                            String keyLabel, RsaCapsuleClient serverClient)
            throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(serverClient);

        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException(INVALID_FMK_LEN);
        }

        RSAPubKeyRecipient rsaPubKeyRecipient = buildRsaRecipient(fmk, recipientPubKey, keyLabel);

        String transactionId = serverClient.storeRsaCapsule(
                recipientPubKey, rsaPubKeyRecipient.getEncryptedKek()
        );

        String serverId = serverClient.getServerIdentifier();

        return new RSAServerKeyRecipient(recipientPubKey, serverId, transactionId,
                rsaPubKeyRecipient.getEncryptedFileMasterKey(), keyLabel);
    }

    /**
     * Derive KEK from preSharedKey, keyLabel and generated salt and encrypt fmk with derived KEK
     * @param fmk          fmk to be encrypted
     * @param preSharedKey pre-shared key, composed of the secret
     * @param keyLabel     key label
     * @param fmkEncMethod FMKEncryptionMethod
     * @return SymmetricKeyRecipient that can be serialized into FBS {@link SymmetricKeyCapsule}
     * @throws GeneralSecurityException
     */
    static SymmetricKeyRecipient buildSymmetricKeyRecipient(byte[] fmk, SecretKey preSharedKey,
                String keyLabel, String fmkEncMethod) throws GeneralSecurityException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(preSharedKey);
        Objects.requireNonNull(keyLabel);

        byte[] salt = new byte[256 / 8]; //spec: salt length should be 256bits
        Crypto.getSecureRandom().nextBytes(salt);

        SecretKey kek = Crypto.deriveKeyEncryptionKey(keyLabel, preSharedKey, salt, fmkEncMethod);

        byte[] encryptedFmk = Crypto.xor(fmk, kek.getEncoded());
        return new SymmetricKeyRecipient(salt, encryptedFmk, keyLabel);
    }

    /**
     * Derive KEK from preSharedKey and keyLabel and encrypt fmk with derived KEK
     * @param fmk          fmk to be encrypted
     * @param preSharedKey pre-shared key, composed of the password
     * @param keyLabel     key label
     * @param fmkEncMethod FMKEncryptionMethod
     * @return PBKDF2Recipient that can be serialized into FBS {@link PBKDF2Capsule}
     */
    static PBKDF2Recipient buildPBKDF2Recipient(
        byte[] fmk, SecretKey preSharedKey, String keyLabel, String fmkEncMethod
    ) {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(preSharedKey);
        Objects.requireNonNull(keyLabel);

        byte[] salt = keyLabel.getBytes(StandardCharsets.UTF_8);
        SecretKey kek = Crypto.deriveKeyEncryptionKey(keyLabel, preSharedKey, salt, fmkEncMethod);

        byte[] encryptedFmk = Crypto.xor(fmk, kek.getEncoded());
        return new PBKDF2Recipient(salt, encryptedFmk, keyLabel);
    }

}
