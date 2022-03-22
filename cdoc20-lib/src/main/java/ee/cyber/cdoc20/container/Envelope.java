package ee.cyber.cdoc20.container;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.crypto.ChaChaCipher;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.fbs.header.*;
import ee.cyber.cdoc20.fbs.header.Header;
import ee.cyber.cdoc20.fbs.recipients.ECCPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class Envelope {
    private static final Logger log = LoggerFactory.getLogger(Envelope.class);


    public static final byte[] PRELUDE = {'C', 'D', 'O', 'C'};
    public static final byte VERSION = 2;


    //public static final int HDR_HMAC_LEN_BYTES = 32;

    private static final byte payloadEncByte = PayloadEncryptionMethod.CHACHA20POLY1305;

    //private final byte[] fmkKeyBuf;
    private final EccRecipient[] eccRecipients;

    private final SecretKey hmacKey;

    //content encryption  key
    private final SecretKey cekKey;

    private Envelope(EccRecipient[] recipients, SecretKey hmacKey, SecretKey cekKey) {
        //this.fmkKeyBuf = fmkKey;
        this.eccRecipients = recipients;
        this.hmacKey = hmacKey;
        this.cekKey = cekKey;
    }

    public static Envelope build(byte[] fmk, KeyPair senderEcKeyPair, List<ECPublicKey> recipients) throws NoSuchAlgorithmException, InvalidKeyException {
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Invalid FMK len");
        }

        List<EccRecipient> eccRecipientList = new LinkedList<>();

        for (ECPublicKey otherPubKey: recipients) {
            byte[] kek = Crypto.deriveKeyEncryptionKey(senderEcKeyPair, otherPubKey, Crypto.CEK_LEN_BYTES);
            byte[] encryptedFmk = Crypto.xor(fmk, kek);
            EccRecipient eccRecipient = new EccRecipient(otherPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk);
            eccRecipientList.add(eccRecipient);
        }

        SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
        SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);
        return new Envelope(eccRecipientList.toArray(new EccRecipient[0]), hmacKey, cekKey);
    }

    public void serialize(InputStream payloadIs, OutputStream os) throws IOException {
        os.write(PRELUDE);
        os.write(new byte[]{VERSION});

        byte[] headerBytes = serializeHeader();

        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putInt(headerBytes.length);
        byte[] headerLenBytes = bb.array();

        os.write(headerLenBytes);
        os.write(headerBytes);


        try {
            byte[] hmac = Crypto.calcHmacSha256(hmacKey, headerBytes);
            os.write(hmac);
            byte[] nonce = ChaChaCipher.generateNonce();
            byte[] additionalData = ChaChaCipher.getAdditionalData(headerBytes, hmac);
            CipherOutputStream cipherOs = ChaChaCipher.initChaChaOutputStream(os, cekKey, nonce, additionalData);
            cipherOs.write(payloadIs.readAllBytes()); //TODO: tar, zip, loop before encryption

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            log.error("error serializing payload", e);
            throw new IOException("error serializing payload", e);
        }
    }

    byte[] serializeHeader() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        serializeHeader(baos);
        return baos.toByteArray();
    }

    void serializeHeader(OutputStream os) throws IOException {
        FlatBufferBuilder builder = new FlatBufferBuilder(1024);


        int[] recipients = new int[eccRecipients.length];

        for (int i = 0; i < eccRecipients.length; i++) {
            EccRecipient eccRecipient = eccRecipients[i];

            int recipientPubKeyOffset = builder.createByteVector(eccRecipient.getRecipientPubKeyTlsEncoded()); // TLS 1.3 format
            int senderPubKeyOffset = builder.createByteVector(eccRecipient.getSenderPubKeyTlsEncoded()); // TLS 1.3 format
            int eccPubKeyOffset = ECCPublicKey.createECCPublicKey(builder,
                    eccRecipient.ellipticCurve,
                    recipientPubKeyOffset,
                    senderPubKeyOffset
            );

            int encFmkOffset =
                    RecipientRecord.createEncryptedFmkVector(builder, eccRecipient.getEncryptedFileMasterKey());

            RecipientRecord.startRecipientRecord(builder);
            RecipientRecord.addDetailsType(builder, Details.recipients_ECCPublicKey);
            RecipientRecord.addDetails(builder, eccPubKeyOffset);

            RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
            RecipientRecord.addFmkEncryptionMethod(builder, FMKEncryptionMethod.XOR);

            int recipientOffset = RecipientRecord.endRecipientRecord(builder);

            recipients[i] = recipientOffset;
        }

        int recipientsOffset = Header.createRecipientsVector(builder, recipients);

        Header.startHeader(builder);
        Header.addRecipients(builder, recipientsOffset);
        Header.addPayloadEncryptionMethod(builder, payloadEncByte);
        int headerOffset = Header.endHeader(builder);
        Header.finishHeaderBuffer(builder, headerOffset);

        ByteBuffer buf = builder.dataBuffer();
        int bufLen = buf.limit() - buf.position();
        os.write(buf.array(), buf.position(), bufLen);
    }






}
