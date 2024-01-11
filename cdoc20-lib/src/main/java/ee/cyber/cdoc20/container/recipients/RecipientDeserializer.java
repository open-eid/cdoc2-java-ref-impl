package ee.cyber.cdoc20.container.recipients;

import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.container.UnknownFlatBufferTypeException;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import ee.cyber.cdoc20.crypto.RsaUtils;
import ee.cyber.cdoc20.fbs.header.RecipientRecord;
import ee.cyber.cdoc20.fbs.recipients.ECCPublicKeyCapsule;
import ee.cyber.cdoc20.fbs.recipients.EccKeyDetails;
import ee.cyber.cdoc20.fbs.recipients.KeyDetailsUnion;
import ee.cyber.cdoc20.fbs.recipients.KeyServerCapsule;
import ee.cyber.cdoc20.fbs.recipients.PBKDF2Capsule;
import ee.cyber.cdoc20.fbs.recipients.RSAPublicKeyCapsule;
import ee.cyber.cdoc20.fbs.recipients.RsaKeyDetails;
import ee.cyber.cdoc20.fbs.recipients.SymmetricKeyCapsule;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static ee.cyber.cdoc20.fbs.header.Capsule.*;

/**
 * Deserialize Recipient from flatbuffers RecipientRecord
 */
public final class RecipientDeserializer {

    private RecipientDeserializer() { }

    public static Recipient deserialize(RecipientRecord r)
        throws CDocParseException, GeneralSecurityException {

        if (r.fmkEncryptionMethod() != Envelope.FMK_ENC_METHOD_BYTE) {
            throw new CDocParseException("Unknown FMK encryption method: " + r.fmkEncryptionMethod());
        }

        if (r.encryptedFmkLength() != Crypto.FMK_LEN_BYTES) {
            throw new CDocParseException("invalid FMK len: " + r.encryptedFmkLength());
        }

        ByteBuffer encryptedFmkBuf = r.encryptedFmkAsByteBuffer();
        byte[] encryptedFmkBytes = Arrays.copyOfRange(encryptedFmkBuf.array(),
                encryptedFmkBuf.position(), encryptedFmkBuf.limit());
        String keyLabel = r.keyLabel();

        return getDeserializedRecipientByKeyOrigin(r, encryptedFmkBytes, keyLabel);
    }

    private static Recipient getDeserializedRecipientByKeyOrigin(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel
    ) throws GeneralSecurityException, CDocParseException {
        if (r.capsuleType() == recipients_ECCPublicKeyCapsule) {

            return deserializeEccPubKeyRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_RSAPublicKeyCapsule) {

            return deserializeRsaPubKeyRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_KeyServerCapsule) {

            return deserializeServerRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_SymmetricKeyCapsule) {

            return deserializeSymmetricKeyRecipient(r, encryptedFmkBytes, keyLabel);
        } else if (r.capsuleType() == recipients_PBKDF2Capsule) {

            return deserializePBKDF2Recipient(r, encryptedFmkBytes, keyLabel);
        } else {
            throw new UnknownFlatBufferTypeException("Unknown recipient type " + r.capsuleType());
        }
    }

    private static SymmetricKeyRecipient deserializeSymmetricKeyRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel)
        throws CDocParseException {

        SymmetricKeyCapsule symmetricKeyCapsule = (SymmetricKeyCapsule) r.capsule(new SymmetricKeyCapsule());
        if (symmetricKeyCapsule == null) {
            throw new CDocParseException("error parsing SymmetricKeyCapsule");
        }

        ByteBuffer saltBuf = symmetricKeyCapsule.saltAsByteBuffer();
        byte[] salt = Arrays.copyOfRange(saltBuf.array(), saltBuf.position(), saltBuf.limit());
        return new SymmetricKeyRecipient(salt, encryptedFmkBytes, keyLabel);
    }

    private static PBKDF2Recipient deserializePBKDF2Recipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel)
        throws CDocParseException {

        PBKDF2Capsule pbkdf2Capsule = (PBKDF2Capsule) r.capsule(new PBKDF2Capsule());
        if (pbkdf2Capsule == null) {
            throw new CDocParseException("error parsing PBKDF2Capsule");
        }

        ByteBuffer saltBuf = pbkdf2Capsule.saltAsByteBuffer();
        byte[] salt = Arrays.copyOfRange(saltBuf.array(), saltBuf.position(), saltBuf.limit());
        return new PBKDF2Recipient(salt, encryptedFmkBytes, keyLabel);
    }

    private static Recipient deserializeServerRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel)
        throws CDocParseException, GeneralSecurityException {

        KeyServerCapsule serverCapsule = (KeyServerCapsule) r.capsule(new KeyServerCapsule());
        if (serverCapsule == null) {
            throw new CDocParseException("error parsing KeyServerCapsule");
        }

        if (serverCapsule.recipientKeyDetailsType() == KeyDetailsUnion.EccKeyDetails) {
            EccKeyDetails serverEccDetails =
                    (EccKeyDetails) serverCapsule.recipientKeyDetails(new EccKeyDetails());
            if (serverEccDetails == null) {
                throw new CDocParseException("error parsing EccKeyDetails");
            }

            ECPublicKey recipientPubKey;
            EllipticCurve curve = EllipticCurve.forValue(serverEccDetails.curve());
            try {
                ByteBuffer recipientPubKeyBuf = serverEccDetails.recipientPublicKeyAsByteBuffer();
                recipientPubKey = curve.decodeFromTls(recipientPubKeyBuf);
            } catch (IllegalArgumentException iae) {
                throw new CDocParseException("illegal EC pub key encoding", iae);
            }
            String keyServerId = serverCapsule.keyserverId();
            String transactionId = serverCapsule.transactionId();

            return new EccServerKeyRecipient(curve, recipientPubKey, keyServerId,
                    transactionId, encryptedFmkBytes, keyLabel);
        } else if (serverCapsule.recipientKeyDetailsType() == KeyDetailsUnion.RsaKeyDetails) {

            RsaKeyDetails serverRsaDetails =
                    (RsaKeyDetails) serverCapsule.recipientKeyDetails(new RsaKeyDetails());
            if (serverRsaDetails == null) {
                throw new CDocParseException("error parsing RsaKeyDetails");
            }

            RSAPublicKey recipientPubKey;
            try {
                recipientPubKey = RsaUtils.decodeRsaPubKey(serverRsaDetails.recipientPublicKeyAsByteBuffer());
            } catch (IOException e) {
                throw new CDocParseException("error parsing RsaKeyDetails.recipientPubKey");
            }

            String keyServerId = serverCapsule.keyserverId();
            String transactionId = serverCapsule.transactionId();

            return new RSAServerKeyRecipient(recipientPubKey, keyServerId, transactionId,
                    encryptedFmkBytes, keyLabel);

        } else {
            throw new UnknownFlatBufferTypeException(
                    "Unknown KeyServerCapsule.recipient_key_details type (KeyDetailsUnion) "
                            + serverCapsule.recipientKeyDetailsType());
        }
    }

    private static RSAPubKeyRecipient deserializeRsaPubKeyRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel) throws CDocParseException {
        RSAPublicKeyCapsule rsaPublicKeyCapsule = (RSAPublicKeyCapsule) r.capsule(new RSAPublicKeyCapsule());
        if (rsaPublicKeyCapsule == null) {
            throw new CDocParseException("error parsing RSAPublicKeyCapsule");
        }

        ByteBuffer rsaPubKeyBuf = rsaPublicKeyCapsule.recipientPublicKeyAsByteBuffer();
        if (rsaPubKeyBuf == null) {
            throw new CDocParseException("error parsing RSAPublicKeyCapsule.recipientPublicKey");
        }

        ByteBuffer encKekBuf = rsaPublicKeyCapsule.encryptedKekAsByteBuffer();
        if (encKekBuf == null) {
            throw new CDocParseException("error parsing RSAPublicKeyCapsule.encryptedKek");
        }

        byte[] rsaPubKeyBytes =
                Arrays.copyOfRange(rsaPubKeyBuf.array(), rsaPubKeyBuf.position(), rsaPubKeyBuf.limit());
        RSAPublicKey recipientRsaPublicKey;

        try {
            recipientRsaPublicKey = RsaUtils.decodeRsaPubKey(rsaPubKeyBytes);
        } catch (GeneralSecurityException | IOException ex) {
            throw new CDocParseException("error decoding RSAPublicKey", ex);
        }

        byte[] encKek = Arrays.copyOfRange(encKekBuf.array(), encKekBuf.position(), encKekBuf.limit());

        return new RSAPubKeyRecipient(recipientRsaPublicKey, encKek, encryptedFmkBytes, keyLabel);
    }

    private static  EccPubKeyRecipient deserializeEccPubKeyRecipient(
        RecipientRecord r, byte[] encryptedFmkBytes, String keyLabel)
        throws CDocParseException, GeneralSecurityException {

        ECCPublicKeyCapsule eccPublicKeyCapsule = (ECCPublicKeyCapsule) r.capsule(new ECCPublicKeyCapsule());
        if (eccPublicKeyCapsule == null) {
            throw new CDocParseException("error parsing ECCPublicKeyCapsule");
        }

        try {
            EllipticCurve curve = EllipticCurve.forValue(eccPublicKeyCapsule.curve());
            ECPublicKey recipientPubKey =
                    curve.decodeFromTls(eccPublicKeyCapsule.recipientPublicKeyAsByteBuffer());
            ECPublicKey senderPubKey =
                    curve.decodeFromTls(eccPublicKeyCapsule.senderPublicKeyAsByteBuffer());

            return new EccPubKeyRecipient(curve, recipientPubKey, senderPubKey,
                    encryptedFmkBytes, keyLabel);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new CDocParseException("illegal EC pub key encoding", illegalArgumentException);
        }
    }
}
