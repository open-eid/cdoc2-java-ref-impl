package ee.cyber.cdoc20.container;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.fbs.header.*;
import ee.cyber.cdoc20.fbs.header.Header;
import ee.cyber.cdoc20.fbs.recipients.ECCPublicKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Envelope {
    public static final byte[] PRELUDE = {'C', 'D', 'O', 'C'};
    public static final byte VERSION = 2;


    public static final int HDR_HMAC_LEN_BYTES = 32;

    private final byte payloadEncByte = PayloadEncryptionMethod.CHACHA20POLY1305;

    private final byte[] fmkKeyBuf;
    private final EccRecipient[] eccRecipients;

    public Envelope(byte[] fmkKey, EccRecipient[] recipients) {
        this.fmkKeyBuf = fmkKey;
        this.eccRecipients = recipients;
    }

    public void serialize(InputStream payload, OutputStream os) throws IOException {
        os.write(PRELUDE);
        os.write(new byte[]{VERSION});

        byte[] headerBytes = serializeHeader();

        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putInt(headerBytes.length);
        byte[] beInt = bb.array();
        os.write(bb.array());

        os.write(headerBytes);

        os.write(new byte[HDR_HMAC_LEN_BYTES]);// TODO: calculate hmac

        os.write(payload.readAllBytes()); //TODO: tar, zip, encrypt




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
