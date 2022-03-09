package ee.cyber.cdoc20.container;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

class EnvelopeTest {
    public static final int KEYLEN_BYTES = 256 / 8;

    byte[] fmkBuf =  new byte[KEYLEN_BYTES];
    byte[] recipientPubKeyBuf = new byte[KEYLEN_BYTES];
    byte[] senderPubKeyBuf = new byte[KEYLEN_BYTES];

    @BeforeEach
    void initTestBuffers() {
        fmkBuf[0] = 'f';
        fmkBuf[1] = 'm';
        fmkBuf[2] = 'k';
        fmkBuf[fmkBuf.length - 1] = (byte)0xff;

        recipientPubKeyBuf[0] = 'r';
        recipientPubKeyBuf[1] = 'e';
        recipientPubKeyBuf[2] = 'c';
        recipientPubKeyBuf[recipientPubKeyBuf.length - 1] = (byte)0xfe;

        senderPubKeyBuf[0] = 's';
        senderPubKeyBuf[1] = 'e';
        senderPubKeyBuf[2] = 'n';
        senderPubKeyBuf[senderPubKeyBuf.length - 1]  = (byte)0xfc;
    }

    @Test
    void serializeHeaderTest() throws IOException {

        EccRecipient [] eccRecipients = new EccRecipient[] {new EccRecipient(recipientPubKeyBuf, senderPubKeyBuf)};
        //InputStream payloadIs = new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8));
        Envelope envelope = new Envelope(fmkBuf, eccRecipients);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        envelope.serializeHeader(baos);

        byte[] headerBytes = baos.toByteArray();

        assertTrue(headerBytes.length > 0);

        //TODO: check that header can be de-serialized
    }

    @Test
    void testContainer() throws IOException {
        EccRecipient [] eccRecipients = new EccRecipient[] {new EccRecipient(recipientPubKeyBuf, senderPubKeyBuf)};
        InputStream payload = new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8));
        Envelope envelope = new Envelope(fmkBuf, eccRecipients);

        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.serialize(payload, dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

    }
}