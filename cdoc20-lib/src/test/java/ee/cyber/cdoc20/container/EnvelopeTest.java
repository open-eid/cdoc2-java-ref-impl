package ee.cyber.cdoc20.container;

import static java.util.Base64.getEncoder;
import static org.junit.jupiter.api.Assertions.*;

import ee.cyber.cdoc20.crypto.Crypto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

class EnvelopeTest {
    byte[] fmkBuf =  new byte[Crypto.FMK_LEN_BYTES];
    byte[] recipientPubKeyBuf = new byte[1+48*2];
    byte[] senderPubKeyBuf = new byte[1+48*2];


//    KeyPair recipientKeyPair = Crypto.generateEcKeyPair();
//    String recipientPubKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPublic().getEncoded());
//    String recipientPrivKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPrivate().getEncoded());
//    public static final String recipientPubKeyBase64 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGTr5ojK7f6VnWa2MNceu+BfBnhnejGBpqgi3cKxXxl3huGbBzDCku+/HwYw6R+EqVFHRuVGgspX/QwGzJqxxsxKCEOic3U4hNo4vChF3wMSlTbI2IypZeNdoJybzKXv7";
//    public static final String recipientPrivKeyBase64 = "ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDCFkOQ2qBEWDXFMKwR65pAI1I3Hsao+FBj0jroy0xgMl0W5qrGU9ULnGWGg6l0D3S8=";
// How to decode pub key from X.509 and priv key from PKCS#8 ?

    ECPublicKey recipientPubKey;
    ECPublicKey senderPubKey;

    @BeforeEach
    void initInputData() throws InvalidParameterSpecException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        fmkBuf[0] = 'f';
        fmkBuf[1] = 'm';
        fmkBuf[2] = 'k';
        fmkBuf[fmkBuf.length - 1] = (byte)0xff;

        KeyPair recipientKeyPair = Crypto.generateEcKeyPair();

        KeyPair senderKeyPair = Crypto.generateEcKeyPair();

//        String recipientPubKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPublic().getEncoded());
//        String recipientPrivKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPrivate().getEncoded());
//
//        String senderPubKeyB64 = Base64.getEncoder().encodeToString(senderKeyPair.getPublic().getEncoded());
//        String senderPrivKeyB64 = Base64.getEncoder().encodeToString(senderKeyPair.getPrivate().getEncoded());


        //generate new keys for now as no idea how to decode keys from default encoding (X.509 and PKCS#8)
        this.recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();
        this.senderPubKey = (ECPublicKey) senderKeyPair.getPublic();
    }

    @Test
    void serializeHeaderTest() throws IOException {
        EccRecipient [] eccRecipients = new EccRecipient[] {new EccRecipient(recipientPubKey, senderPubKey, fmkBuf)};
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
        EccRecipient [] eccRecipients = new EccRecipient[] {new EccRecipient(recipientPubKey, senderPubKey, fmkBuf)};
        InputStream payload = new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8));
        Envelope envelope = new Envelope(fmkBuf, eccRecipients);

        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.serialize(payload, dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);
    }
}