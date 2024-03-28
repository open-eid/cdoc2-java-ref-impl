package ee.cyber.cdoc2.container.recipients;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc2.crypto.RsaUtils;
import ee.cyber.cdoc2.fbs.header.Capsule;
import ee.cyber.cdoc2.fbs.header.RecipientRecord;
import ee.cyber.cdoc2.fbs.recipients.ECCPublicKeyCapsule;
import ee.cyber.cdoc2.fbs.recipients.EccKeyDetails;
import ee.cyber.cdoc2.fbs.recipients.KeyDetailsUnion;
import ee.cyber.cdoc2.fbs.recipients.KeyServerCapsule;
import ee.cyber.cdoc2.fbs.recipients.PBKDF2Capsule;
import ee.cyber.cdoc2.fbs.recipients.RSAPublicKeyCapsule;
import ee.cyber.cdoc2.fbs.recipients.RsaKeyDetails;
import ee.cyber.cdoc2.fbs.recipients.SymmetricKeyCapsule;

import static ee.cyber.cdoc2.fbs.header.Capsule.*;

/**
 * Utility class to serialize Recipient into flatbuffers FlatBufferBuilder
 */
public final class RecipientSerializer {

    private RecipientSerializer() { }

    public static int serialize(EccServerKeyRecipient eccServerRecipient, FlatBufferBuilder builder) {

        int recipientPubKeyOffset = builder.createByteVector(eccServerRecipient.getRecipientPubKeyTlsEncoded());

        int serverEccDetailsOffset = EccKeyDetails.createEccKeyDetails(builder,
                eccServerRecipient.getEllipticCurve().getValue(),
                recipientPubKeyOffset
        );

        int keyServerOffset = builder.createString(eccServerRecipient.getKeyServerId());
        int transactionIdOffset = builder.createString(eccServerRecipient.getTransactionId());

        int capsuleOffset = KeyServerCapsule.createKeyServerCapsule(builder,
                KeyDetailsUnion.EccKeyDetails,
                serverEccDetailsOffset,
                keyServerOffset,
                transactionIdOffset
        );

        int encFmkOffset =
                RecipientRecord.createEncryptedFmkVector(builder,
                        eccServerRecipient.getEncryptedFileMasterKey());

        int keyLabelOffset = builder.createString(getKeyLabelValue(eccServerRecipient)); //required field

        return fillRecipientRecord(
            builder,
            recipients_KeyServerCapsule,
            capsuleOffset,
            keyLabelOffset,
            encFmkOffset,
            eccServerRecipient.getFmkEncryptionMethod()
        );
    }

    public static int serialize(EccPubKeyRecipient eccRecipient, FlatBufferBuilder builder) {

        int recipientPubKeyOffset = builder.createByteVector(eccRecipient.getRecipientPubKeyTlsEncoded());
        int senderPubKeyOffset = builder.createByteVector(eccRecipient.getSenderPubKeyTlsEncoded());
        int eccPubKeyOffset = ECCPublicKeyCapsule.createECCPublicKeyCapsule(builder,
                eccRecipient.getEllipticCurve().getValue(),
                recipientPubKeyOffset,
                senderPubKeyOffset
        );

        int encFmkOffset =
                RecipientRecord.createEncryptedFmkVector(builder, eccRecipient.getEncryptedFileMasterKey());

        int keyLabelOffset = builder.createString(getKeyLabelValue(eccRecipient)); //required field

        return fillRecipientRecord(
            builder,
            recipients_ECCPublicKeyCapsule,
            eccPubKeyOffset,
            keyLabelOffset,
            encFmkOffset,
            eccRecipient.getFmkEncryptionMethod()
        );
    }

    public static int serialize(RSAServerKeyRecipient rsaServerRecipient, FlatBufferBuilder builder) {


        byte[] rsaPubKeyDer = RsaUtils.encodeRsaPubKey(rsaServerRecipient.getRecipientPubKey());
        int recipientPubKeyOffset = builder.createByteVector(rsaPubKeyDer);

        int serverRsaDetailsOffset = RsaKeyDetails.createRsaKeyDetails(builder, recipientPubKeyOffset);

        int keyServerOffset = builder.createString(rsaServerRecipient.getKeyServerId());
        int transactionIdOffset = builder.createString(rsaServerRecipient.getTransactionId());

        int capsuleOffset = KeyServerCapsule.createKeyServerCapsule(builder,
                KeyDetailsUnion.RsaKeyDetails,
                serverRsaDetailsOffset,
                keyServerOffset,
                transactionIdOffset
        );

        int encFmkOffset =
                RecipientRecord.createEncryptedFmkVector(builder,
                        rsaServerRecipient.getEncryptedFileMasterKey());

        int keyLabelOffset = builder.createString(getKeyLabelValue(rsaServerRecipient));

        return fillRecipientRecord(
            builder,
            recipients_KeyServerCapsule,
            capsuleOffset,
            keyLabelOffset,
            encFmkOffset,
            rsaServerRecipient.getFmkEncryptionMethod()
        );
    }

    public static int serialize(RSAPubKeyRecipient rsaRecipient, FlatBufferBuilder builder) {

        int recipientPubKeyOffset = builder.createByteVector(
                RsaUtils.encodeRsaPubKey(rsaRecipient.getRecipientPubKey()));
        int encKekOffset = builder.createByteVector(rsaRecipient.getEncryptedKek());
        int rsaPublicKeyCapsule = RSAPublicKeyCapsule.createRSAPublicKeyCapsule(builder,
                recipientPubKeyOffset, encKekOffset);

        int encFmkOffset =
                RecipientRecord.createEncryptedFmkVector(builder, rsaRecipient.getEncryptedFileMasterKey());

        int keyLabelOffset = builder.createString(getKeyLabelValue(rsaRecipient));

        return fillRecipientRecord(
            builder,
            recipients_RSAPublicKeyCapsule,
            rsaPublicKeyCapsule,
            keyLabelOffset,
            encFmkOffset,
            rsaRecipient.getFmkEncryptionMethod()
        );
    }

    public static int serializeSymmetricKeyRecipient(SymmetricKeyRecipient symRecipient, FlatBufferBuilder builder) {

        int saltOffset = builder.createByteVector(symRecipient.getSalt());
        int symmetricKeyCapsuleOffset = SymmetricKeyCapsule.createSymmetricKeyCapsule(builder, saltOffset);
        int encFmkOffset =
                RecipientRecord.createEncryptedFmkVector(builder, symRecipient.getEncryptedFileMasterKey());
        int keyLabelOffset = builder.createString(getKeyLabelValue(symRecipient));

        return fillRecipientRecord(
            builder,
            recipients_SymmetricKeyCapsule,
            symmetricKeyCapsuleOffset,
            keyLabelOffset,
            encFmkOffset,
            symRecipient.getFmkEncryptionMethod()
        );
    }

    public static int serializePBKDF2Recipient(
        PBKDF2Recipient passwordRecipient, FlatBufferBuilder builder
    ) {
        int encSaltOffset = builder.createByteVector(passwordRecipient.getEncryptionSalt());
        int pwSaltOffset = builder.createByteVector(passwordRecipient.getPasswordSalt());
        int passwordCapsuleOffset = PBKDF2Capsule.createPBKDF2Capsule(
            builder,
            encSaltOffset,
            pwSaltOffset,
            passwordRecipient.getKdfAlgorithm(),
            passwordRecipient.getKdfIterations()
        );
        int encFmkOffset =
            RecipientRecord.createEncryptedFmkVector(builder, passwordRecipient.getEncryptedFileMasterKey());
        int keyLabelOffset = builder.createString(getKeyLabelValue(passwordRecipient));

        return fillRecipientRecord(
            builder,
            recipients_PBKDF2Capsule,
            passwordCapsuleOffset,
            keyLabelOffset,
            encFmkOffset,
            passwordRecipient.getFmkEncryptionMethod()
        );
    }

    /**
     * Add RecipientRecord to the end of {@link FlatBufferBuilder builder}
     * @param builder builder to be updated
     * @param capsuleType from {@link Capsule}
     * @param capsuleOffset capsuleOffset in builder
     * @param keyLabelOffset keyLabelOffset in builder
     * @return recipientRecord offset in builder
     */
    private static int fillRecipientRecord(FlatBufferBuilder builder, byte capsuleType, int capsuleOffset,
                                           int keyLabelOffset, int encFmkOffset, byte fmkEncryptionMethod) {

        RecipientRecord.startRecipientRecord(builder);
        RecipientRecord.addCapsuleType(builder, capsuleType);
        RecipientRecord.addCapsule(builder, capsuleOffset);

        RecipientRecord.addKeyLabel(builder, keyLabelOffset);

        RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
        RecipientRecord.addFmkEncryptionMethod(builder, fmkEncryptionMethod);

        return RecipientRecord.endRecipientRecord(builder);
    }

    /**
     * Get value for FBS RecipientRecord.key_label
     * @param recipient recipient to generate key label from
     * @return key label that describes recipient
     */
    private static String getKeyLabelValue(Recipient recipient) {
        // KeyLabel is UI specific field, so its value is not specified in the Spec.
        // Required to be filled or deserialization will fail.
        // DigiDoc4-Client uses this field to hint user what type of eID was used for encryption
        // https://github.com
        // /open-eid/DigiDoc4-Client/blob/f4298ad9d2fbb40cffc488bed6cf1d3116dff450/client/SslCertificate.cpp#L302
        // https://github.com/open-eid/DigiDoc4-Client/blob/master/client/dialogs/AddRecipients.cpp#L474

        if (recipient.getRecipientKeyLabel() != null) {
            return recipient.getRecipientKeyLabel();
        } else {
            return "N/A"; //can't be empty
        }
    }
}
