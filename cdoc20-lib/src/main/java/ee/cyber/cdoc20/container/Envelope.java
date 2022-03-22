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
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;

public class Envelope {
    private static final Logger log = LoggerFactory.getLogger(Envelope.class);


    public static final byte[] PRELUDE = {'C', 'D', 'O', 'C'};
    public static final byte VERSION = 2;

    public static final int MIN_HEADER_LEN = 1; //TODO: find out min header len


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
            log.debug("encrypted FMK: {}", HexFormat.of().formatHex(encryptedFmk));
            eccRecipientList.add(eccRecipient);
        }

        SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
        SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);
        return new Envelope(eccRecipientList.toArray(new EccRecipient[0]), hmacKey, cekKey);
    }

    //TODO: parseHeader return type not final
    public static List<EccRecipient> parseHeader(InputStream envelopeIs) throws IOException, CDocParseException, GeneralSecurityException {
        final int envelope_min_len = PRELUDE.length
                + 1 //version 0x02
                + 4 //header length field
                + MIN_HEADER_LEN
                + Crypto.HHK_LEN_BYTES
                + 0 // TODO: payload min size
        ;

        if (envelopeIs.available() < envelope_min_len) {
            throw new CDocParseException("not enough bytes to read, expected min of " + envelope_min_len);
        }

        if (!Arrays.equals(PRELUDE, envelopeIs.readNBytes(PRELUDE.length))) {
            throw new CDocParseException("stream is not CDOC");
        }

        byte version = (byte) envelopeIs.read();
        if (VERSION != version) {
            throw new CDocParseException("Unsupported CDOC version " + version);
        }

        ByteBuffer headerLenBuf = ByteBuffer.allocate(4);
        headerLenBuf.order(ByteOrder.BIG_ENDIAN);
        envelopeIs.read(headerLenBuf.array());
        int headerLen = headerLenBuf.getInt();

        if ((envelopeIs.available() < headerLen + Crypto.HHK_LEN_BYTES)
            || (headerLen < MIN_HEADER_LEN))  {
            throw new CDocParseException("invalid CDOC header length: "+headerLen);
        }

        byte[] headerBytes = envelopeIs.readNBytes(headerLen + Crypto.HHK_LEN_BYTES);

        Header header = deserializeHeader(headerBytes);

        List<EccRecipient> eccRecipientList = new LinkedList<>();

        for (int i=0; i < header.recipientsLength(); i++) {
            RecipientRecord r = header.recipients(i);

            if( FMKEncryptionMethod.XOR != r.fmkEncryptionMethod() ) {
                throw new CDocParseException("invalid FMK encryption method: "+r.fmkEncryptionMethod());
            }

            if (r.encryptedFmkLength() != Crypto.FMK_LEN_BYTES) {
                throw new CDocParseException("invalid FMK len: "+ r.encryptedFmkLength());
            }

            ByteBuffer encryptedFmkBuf = r.encryptedFmkAsByteBuffer();
            byte[] encryptedFmkBytes = Arrays.copyOfRange(encryptedFmkBuf.array(),
                    encryptedFmkBuf.position(), encryptedFmkBuf.limit());

            log.debug("Parsed encrypted FMK: {}", HexFormat.of().formatHex(encryptedFmkBytes));

            if ( r.detailsType() == Details.recipients_ECCPublicKey) {
                ECCPublicKey detailsEccPublicKey = (ECCPublicKey) r.details(new ECCPublicKey());
                if (detailsEccPublicKey == null) {
                    throw new CDocParseException("error parsing Details");
                }

                try {
                    ECPublicKey recipientPubKey = Crypto.decodeEcPublicKeyFromTls(detailsEccPublicKey.recipientPublicKeyAsByteBuffer());
                    ECPublicKey senderPubKey = Crypto.decodeEcPublicKeyFromTls(detailsEccPublicKey.senderPublicKeyAsByteBuffer());

                    eccRecipientList.add(new EccRecipient(r.fmkEncryptionMethod(),
                            recipientPubKey, senderPubKey, encryptedFmkBytes));
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new CDocParseException("illegal EC pub key encoding", illegalArgumentException);
                }
            } else if (r.detailsType() == Details.recipients_KeyServer){
                log.warn("Details.recipients_KeyServer not implemented");
            } else if (r.detailsType() == Details.NONE){
                log.warn("Details.NONE not implemented");
            }
            else {
                log.error("Unknown Details type {}", r.detailsType());
                throw new CDocParseException("Unknown Details type "+r.detailsType());
            }
        }

        return eccRecipientList;
    }

    static Header deserializeHeader(byte[] buf) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
        Header header =  Header.getRootAsHeader(byteBuffer);
        return header;
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
