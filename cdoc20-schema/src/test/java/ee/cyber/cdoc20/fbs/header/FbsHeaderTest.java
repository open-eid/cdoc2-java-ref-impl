package ee.cyber.cdoc20.fbs.header;

import ee.cyber.cdoc20.fbs.recipients.EllipticCurve;
import ee.cyber.cdoc20.fbs.recipients.KeyServerDetails;
import ee.cyber.cdoc20.fbs.recipients.ServerDetailsUnion;
import ee.cyber.cdoc20.fbs.recipients.ServerEccDetails;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.google.flatbuffers.FlatBufferBuilder;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static ee.cyber.cdoc20.fbs.header.Details.recipients_KeyServerDetails;

class FbsHeaderTest {

    public static final int KEYLEN_BYTES = 256 / 8;

    @Test
    void testFbsHeaderSerialization() throws IOException {

        byte payloadEnc = PayloadEncryptionMethod.CHACHA20POLY1305;

        byte[] fmkBuf =  new byte[KEYLEN_BYTES];
        fmkBuf[0] = 'f';
        fmkBuf[1] = 'm';
        fmkBuf[2] = 'k';
        fmkBuf[fmkBuf.length - 1] = (byte)0xff;


        byte[] recipientPubKeyBuf = new byte[KEYLEN_BYTES];
        recipientPubKeyBuf[0] = 'r';
        recipientPubKeyBuf[1] = 'e';
        recipientPubKeyBuf[2] = 'c';
        recipientPubKeyBuf[recipientPubKeyBuf.length - 1] = (byte)0xfe;


        byte[] senderPubKeyBuf = new byte[KEYLEN_BYTES];
        senderPubKeyBuf[0] = 's';
        senderPubKeyBuf[1] = 'e';
        senderPubKeyBuf[2] = 'n';
        senderPubKeyBuf[senderPubKeyBuf.length - 1]  = (byte)0xfc;

        String keyLabel = "id-kaart";

        FlatBufferBuilder builder = new FlatBufferBuilder(1024);
        int recipientPubKeyOffset = builder.createByteVector(recipientPubKeyBuf);

        int serverEccDetailsOffset = ServerEccDetails.createServerEccDetails(builder,
                EllipticCurve.secp384r1,
                recipientPubKeyOffset
        );

        int keyServerOffset = builder.createString("keyserver");
        int transactionIdOffset = builder.createString("SD1234567890");


        int detailsOffset  = KeyServerDetails.createKeyServerDetails(builder,
                ServerDetailsUnion.ServerEccDetails,
                serverEccDetailsOffset,
                keyServerOffset,
                transactionIdOffset
        );


        int encFmkOffset = RecipientRecord.createEncryptedFmkVector(builder, fmkBuf);

        int keyLabelOffset = builder.createString(keyLabel);

        RecipientRecord.startRecipientRecord(builder);
        RecipientRecord.addDetailsType(builder, recipients_KeyServerDetails);
        RecipientRecord.addDetails(builder, detailsOffset);

        RecipientRecord.addKeyLabel(builder, keyLabelOffset);

        RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
        RecipientRecord.addFmkEncryptionMethod(builder, FMKEncryptionMethod.XOR);


        // endRecipientRecord will return RecipientRecord offset value
        int[] recipients = new int[] {RecipientRecord.endRecipientRecord(builder)};
        int recipientsOffset = Header.createRecipientsVector(builder, recipients);

        Header.startHeader(builder);
        Header.addRecipients(builder, recipientsOffset);
        Header.addPayloadEncryptionMethod(builder, payloadEnc);
        int headerOffset = Header.endHeader(builder);
        Header.finishHeaderBuffer(builder, headerOffset);

        ByteBuffer buf = builder.dataBuffer();

// temp examples generation
//        FileChannel fc = new FileOutputStream("target/Header.bin").getChannel();
//        int pos = buf.position();
//        int limit = buf.limit();
//        fc.write(buf);
//        fc.close();
//
//        buf.position(pos);
//        buf.limit(limit);

        Header header = Header.getRootAsHeader(buf);

        Assertions.assertNotNull(header);

        Assertions.assertEquals(payloadEnc, header.payloadEncryptionMethod());

        Assertions.assertEquals(1, header.recipientsLength());
        RecipientRecord recipient = header.recipients(0);


        Assertions.assertEquals(recipients_KeyServerDetails, recipient.detailsType());

        KeyServerDetails keyServerDetails = (KeyServerDetails) recipient.details(new KeyServerDetails());
        Assertions.assertNotNull(keyServerDetails);
        Assertions.assertEquals(ServerDetailsUnion.ServerEccDetails, keyServerDetails.recipientKeyDetailsType());

        ServerEccDetails serverEccDetails =
                (ServerEccDetails) keyServerDetails.recipientKeyDetails(new ServerEccDetails());
        Assertions.assertNotNull(serverEccDetails);
        Assertions.assertEquals(EllipticCurve.secp384r1, serverEccDetails.curve());
        Assertions.assertEquals(recipientPubKeyBuf.length, serverEccDetails.recipientPublicKeyLength());

        Assertions.assertNotNull(serverEccDetails.recipientPublicKeyAsByteBuffer());

        byte[] recipientPubKeyBytesOut = new byte[recipientPubKeyBuf.length];
        serverEccDetails.recipientPublicKeyAsByteBuffer().get(
                serverEccDetails.recipientPublicKeyAsByteBuffer().position(),
                recipientPubKeyBytesOut);

        Assertions.assertArrayEquals(recipientPubKeyBuf, recipientPubKeyBytesOut );


        Assertions.assertNotNull(recipient.encryptedFmkAsByteBuffer());
        Assertions.assertEquals(fmkBuf.length, recipient.encryptedFmkLength());

        Assertions.assertEquals(keyLabel, recipient.keyLabel());

        Assertions.assertEquals(fmkBuf[0], (byte)recipient.encryptedFmk(0));

        //whole underlying bytebuffer, with position() set to start of fmkBuf and limit() at end of fmkBuf
        ByteBuffer byteBuffer = recipient.encryptedFmkAsByteBuffer();

        byte[] fmkArray = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());

        //preferred for speed
        byte[] fmkBytes = new byte[KEYLEN_BYTES];
        byteBuffer.get(byteBuffer.position(), fmkBytes);

        Assertions.assertArrayEquals(fmkBuf, fmkArray);
        Assertions.assertArrayEquals(fmkBuf, fmkBytes);
        Assertions.assertEquals(ByteBuffer.wrap(fmkBuf), byteBuffer.slice());
    }
}
