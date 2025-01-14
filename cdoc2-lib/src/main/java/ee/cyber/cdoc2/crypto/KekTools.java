package ee.cyber.cdoc2.crypto;

import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.container.CDocParseException;
import ee.cyber.cdoc2.container.recipients.EccPubKeyRecipient;
import ee.cyber.cdoc2.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc2.container.recipients.KeySharesRecipient;
import ee.cyber.cdoc2.container.recipients.PBKDF2Recipient;
import ee.cyber.cdoc2.container.recipients.RSAPubKeyRecipient;
import ee.cyber.cdoc2.container.recipients.SymmetricKeyRecipient;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyPairDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyShareDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.PasswordDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SecretDecryptionKeyMaterial;
import ee.cyber.cdoc2.exceptions.AuthSignatureCreationException;
import ee.cyber.cdoc2.exceptions.CDocException;
import ee.cyber.cdoc2.exceptions.CDocUserException;
import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.client.EcCapsuleClient;
import ee.cyber.cdoc2.client.EcCapsuleClientImpl;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.client.RsaCapsuleClient;
import ee.cyber.cdoc2.client.RsaCapsuleClientImpl;
import ee.cyber.cdoc2.container.recipients.RSAServerKeyRecipient;
import ee.cyber.cdoc2.fbs.header.FMKEncryptionMethod;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import javax.crypto.SecretKey;

import ee.cyber.cdoc2.util.SIDAuthTokenCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc2.crypto.AuthenticationIdentifier.ETSI_IDENTIFIER_PREFIX;


/**
 * Functions for deriving KEK in different scenarios
 */
public final class KekTools {

    private static final Logger log = LoggerFactory.getLogger(KekTools.class);
    private static final String MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO =
            "must contain RSA key pair for RSA scenario";

    private KekTools() { }


    public static byte[] deriveKekForSymmetricKey(
        SymmetricKeyRecipient recipient,
        SecretDecryptionKeyMaterial keyMaterial
    ) {
        validateKeyOrigin(
            EncryptionKeyOrigin.SECRET,
            keyMaterial.getKeyOrigin(),
            "Expected SecretKey for SymmetricKeyRecipient"
        );

        SecretKey secretKey = keyMaterial.getSecretKey();

        log.debug("KekTools.deriveKekForSymmetricKey keyLabel={}", recipient.getRecipientKeyLabel());
        SecretKey kek = Crypto.deriveKeyEncryptionKey(recipient.getRecipientKeyLabel(),
            secretKey,
            recipient.getSalt(),
            FMKEncryptionMethod.name(recipient.getFmkEncryptionMethod()));
        return kek.getEncoded();
    }

    public static byte[] deriveKekForPasswordDerivedKey(
        PBKDF2Recipient recipient,
        PasswordDecryptionKeyMaterial keyMaterial
    ) throws GeneralSecurityException {

        validateKeyOrigin(
            EncryptionKeyOrigin.PASSWORD,
            keyMaterial.getKeyOrigin(),
            "Expected SecretKey for PBKDF2Recipient"
        );

        SecretKey pwDerivedSymmetricKey = Crypto.extractSymmetricKeyFromPassword(
            keyMaterial.getPassword(),
            recipient.getPasswordSalt()
        );

        SecretKey kek = Crypto.deriveKeyEncryptionKey(recipient.getRecipientKeyLabel(),
            pwDerivedSymmetricKey,
            recipient.getEncryptionSalt(),
            FMKEncryptionMethod.name(recipient.getFmkEncryptionMethod()));
        return kek.getEncoded();
    }

    public static byte[] deriveKekForEcc(
        EccPubKeyRecipient eccPubKeyRecipient,
        KeyPairDecryptionKeyMaterial keyMaterial
    ) throws GeneralSecurityException {

        ECPublicKey senderPubKey = eccPubKeyRecipient.getSenderPubKey();

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            "EC key pair required for KEK derive"
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        return Crypto.deriveKeyDecryptionKey(recipientKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
    }

    @SuppressWarnings("java:S2139")
    public static byte[] deriveKekForEccServer(
        EccServerKeyRecipient keyRecipient,
        KeyPairDecryptionKeyMaterial keyMaterial,
        KeyCapsuleClientFactory capsulesClientFac
    ) throws GeneralSecurityException, CDocException {

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            "Must contain EC key pair for ECC Server scenario"
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        String transactionId = keyRecipient.getTransactionId();
        if (transactionId == null) {
            log.error("No transactionId for recipient {}", keyRecipient.getRecipientKeyLabel());
            throw new CDocParseException("TransactionId missing in record");
        }

        String serverId = keyRecipient.getKeyServerId();
        if (serverId == null) {
            log.error("No serverId for recipient {}", keyRecipient.getRecipientKeyLabel());
            throw new CDocUserException(UserErrorCode.SERVER_NOT_FOUND, "serverId missing in record");
        }

        if (capsulesClientFac == null || capsulesClientFac.getForId(serverId) == null) {
            log.error("Configuration not found for server {}", serverId);
            throw new CDocUserException(
                UserErrorCode.SERVER_NOT_FOUND,
                String.format("Configuration not found for server '%s'", serverId)
            );
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
            log.error("Error querying {} for {} ({})", serverId, transactionId, apiException.getMessage());
            throw apiException;
        }
    }

    public static byte[] deriveKekForRsaServer(
        RSAServerKeyRecipient recipient,
        KeyPairDecryptionKeyMaterial keyMaterial,
        KeyCapsuleClientFactory capsulesClientFac
    ) throws GeneralSecurityException, CDocException {

        String transactionId = recipient.getTransactionId();
        String serverId = recipient.getKeyServerId();

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            "Must contain RSA key pair for RSA Server scenario"
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        if (!KeyAlgorithm.isRsaKeysAlgorithm(recipientKeyPair.getPrivate().getAlgorithm())) {
            throw new IllegalArgumentException(MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO);
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
            throw new CDocUserException(
                UserErrorCode.SERVER_NOT_FOUND,
                String.format("Configuration not found for server '%s'", serverId)
            );
        }

        RsaCapsuleClient client = new RsaCapsuleClientImpl(capsulesClientFac.getForId(serverId));
        byte[] encryptedKek = client.getEncryptedKek(transactionId).orElseThrow();

        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) recipientKeyPair.getPrivate();
        return RsaUtils.rsaDecrypt(encryptedKek, rsaPrivateKey);
    }

    public static byte[] deriveKekForRsa(
        RSAPubKeyRecipient rsaPubKeyRecipient,
        KeyPairDecryptionKeyMaterial keyMaterial
    ) throws GeneralSecurityException {

        validateKeyOrigin(
            EncryptionKeyOrigin.PUBLIC_KEY,
            keyMaterial.getKeyOrigin(),
            MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO
        );

        KeyPair recipientKeyPair = keyMaterial.getKeyPair();

        if (!KeyAlgorithm.isRsaKeysAlgorithm(recipientKeyPair.getPrivate().getAlgorithm())) {
            throw new IllegalArgumentException(MUST_CONTAIN_RSA_KEY_PAIR_FOR_RSA_SCENARIO);
        }

        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) recipientKeyPair.getPrivate();
        return RsaUtils.rsaDecrypt(rsaPubKeyRecipient.getEncryptedKek(), rsaPrivateKey);
    }

    private static void validateKeyOrigin(
        EncryptionKeyOrigin expectedKeyOrigin,
        EncryptionKeyOrigin keyOrigin,
        String errorMsg
    ) {
        if (!expectedKeyOrigin.equals(keyOrigin)) {
            throw new IllegalArgumentException(errorMsg);
        }
    }

    /**
     * Derive KEK from shares. Used for SID/MID.
     * @param keySharesRecipient key shares recipient
     * @param keyMaterial key share decryption key material
     * @param keyShareClientFactory key share client factory
     * @return bytes of KEK
     * @throws GeneralSecurityException if key extraction has failed
     */
    public static byte[] deriveKekFromShares(
        KeySharesRecipient keySharesRecipient,
        KeyShareDecryptionKeyMaterial keyMaterial,
        KeyShareClientFactory keyShareClientFactory
    ) throws GeneralSecurityException {
        validateKeyOrigin(
            EncryptionKeyOrigin.KEY_SHARE,
            keyMaterial.getKeyOrigin(),
            "Expected key shares for KeySharesRecipient"
        );
        List<byte[]> listOfShares = new ArrayList<>();

        try {
            addKeyShares(listOfShares, keyMaterial, keySharesRecipient, keyShareClientFactory);
        } catch (AuthSignatureCreationException asce) {
            throw new GeneralSecurityException(asce);
        }

        return Crypto.combineKek(
            listOfShares,
            keyShareClientFactory.getKeySharesConfiguration().getKeySharesServersMinNum()
        );
    }

    private static void addKeyShares(
        List<byte[]> listOfShares,
        KeyShareDecryptionKeyMaterial decryptKeyMaterial,
        KeySharesRecipient keySharesRecipient,
        KeyShareClientFactory keyShareClientFactory
    ) throws GeneralSecurityException, AuthSignatureCreationException {

        //FIXME: write proper implementation with RM-4309, RM-4032, RM-4073
        String semanticsIdentifier = String.valueOf(keySharesRecipient.getRecipientId()) // etsi/PNOEE-48010010101
            .substring(ETSI_IDENTIFIER_PREFIX.length()); // PNOEE-48010010101

        List<KeyShareUri> shares = keySharesRecipient.getKeyShares();

        AuthenticationIdentifier.AuthenticationType authType
            = decryptKeyMaterial.authIdentifier().getAuthType();

        switch (authType) {
            case SID -> {
                SIDAuthTokenCreator tokenCreator = new SIDAuthTokenCreator(
                    semanticsIdentifier,
                    shares,
                    keyShareClientFactory,
                    SIDAuthTokenCreator.getDefaultSIDClient());
                for (KeyShareUri share : shares) {
                    listOfShares.add(extractSharesFromSidRecipient(keyShareClientFactory, tokenCreator, share));
                }
            }
            case MID -> {
                // ToDo connect authentication here. RM-4609
//                    MobileIdUserData userData = new MobileIdUserData(
//                        decryptKeyMaterial.authIdentifier().getMobileNumber(),
//                        decryptKeyMaterial.authIdentifier().getIdCode()
//                    );
//                    MobileIdClient.startAuthentication(userData);
                for (KeyShareUri share : shares) {
                    listOfShares.add(extractSharesFromMidRecipient(keyShareClientFactory, share));
                }
            }
            default -> throw new IllegalStateException(
                "Unexpected authentication type: " + authType
            );
        }
    }

    private static byte[] extractSharesFromSidRecipient(
        KeyShareClientFactory keyShareClientFactory,
        SIDAuthTokenCreator tokenCreator,
        KeyShareUri share
    ) throws GeneralSecurityException {
        KeySharesClient client
            = keyShareClientFactory.getClientForServerUrl(share.serverBaseUrl());
        String authTicket = tokenCreator.getTokenForShareID(share.shareId());
        String authenticatorCertPEM = tokenCreator.getAuthenticatorCertPEM();

        return getKeyShare(share, client, authTicket, authenticatorCertPEM);
    }

    // ToDo add authentication token here. RM-4609
    private static byte[] extractSharesFromMidRecipient(
        KeyShareClientFactory keyShareClientFactory,
//        MIDAuthTokenCreator tokenCreator
        KeyShareUri share
    ) throws GeneralSecurityException {
        KeySharesClient client
            = keyShareClientFactory.getClientForServerUrl(share.serverBaseUrl());
//        String authTicket = tokenCreator.getTokenForShareID(share.shareId());
//        String authenticatorCertPEM = tokenCreator.getAuthenticatorCertPEM();

        return getKeyShare(share, client, null, null);
    }

    private static byte[] getKeyShare(
        KeyShareUri share,
        KeySharesClient client,
        String authTicket,
        String authenticatorCertPEM
    ) throws GeneralSecurityException {
        try {
            return requestKeyShare(share, client, authTicket, authenticatorCertPEM);
        } catch (ExtApiException e) {
            throw new GeneralSecurityException(
                "Failed to derive key encryption key from shares", e
            );
        }
    }

    private static byte[] requestKeyShare(
        KeyShareUri share,
        KeySharesClient client,
        String authTicket,
        String authenticatorCertPEM
    ) throws ExtApiException, GeneralSecurityException {
        Optional<KeyShare> keyShare = client.getKeyShare(
            share.shareId(),
            authTicket,
            authenticatorCertPEM
        );
        if (keyShare.isEmpty()) {
            throw new GeneralSecurityException(
                String.format(
                    "Failed to find share ID %s at server %s",
                    share.shareId(),
                    share.serverBaseUrl()
                )
            );
        }

        return keyShare.get().getShare();
    }

}
