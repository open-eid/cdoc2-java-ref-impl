package ee.cyber.cdoc20.container;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.CDocException;
import ee.cyber.cdoc20.client.ExtApiException;
import ee.cyber.cdoc20.client.KeyCapsuleClient;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.container.recipients.Recipient;
import ee.cyber.cdoc20.container.recipients.RecipientDeserializer;
import ee.cyber.cdoc20.container.recipients.RecipientFactory;
import ee.cyber.cdoc20.crypto.ChaChaCipher;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyMaterial;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.Header;
import ee.cyber.cdoc20.fbs.header.PayloadEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.RecipientRecord;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@SuppressWarnings("checkstyle:FinalClass")
public class Envelope {
    private static final Logger log = LoggerFactory.getLogger(Envelope.class);

    protected static final byte[] PRELUDE = {'C', 'D', 'O', 'C'};
    public static final byte VERSION = 0x02;
    public static final int MIN_HEADER_LEN = 67; //SymmetricKeyCapsule without FBS overhead

    // MIN_HEADER_LEN value:
    // raw lengths in bytes (without FBS overhead) for  single SymmetricKey recipient:

    // capsule_type: 1
    // SymmetricKeyCapsule recipient:
    //   salt: 32
    // encrypted_fmk: 32 //FMK len
    // fmk_encryption_method: 1
    //
    // per header:
    // payload_encryption_method: 1

    // see ChaChaCipherTest.findTarZChaChaCipherStreamMin() and TarGzTest.findZlibMinSize
    public static final int MIN_PAYLOAD_LEN = 45; // cha cha nonce 12 + min zlib compressed tar 17 + Poly1305 MAC 16

    public static final int MAX_HEADER_LEN = 1024 * 1024; //1MB

    /**Minimal valid envelope size in bytes*/
    public static final int MIN_ENVELOPE_SIZE = PRELUDE.length
            + Byte.BYTES //version 0x02
            + Integer.BYTES //header length field
            + MIN_HEADER_LEN
            + Crypto.HHK_LEN_BYTES
            + MIN_PAYLOAD_LEN;

    // payload encryption method
    private static final byte PAYLOAD_ENC_BYTE = PayloadEncryptionMethod.CHACHA20POLY1305;

    //FMK encryption method
    public static final byte FMK_ENC_METHOD_BYTE = FMKEncryptionMethod.XOR;

    private final Recipient[] recipients;
    private final SecretKey hmacKey;
    private final SecretKey cekKey;

    private Envelope(Recipient[] recipients, byte[] fmk) {
        this.recipients = recipients;
        this.hmacKey = Crypto.deriveHeaderHmacKey(fmk);
        this.cekKey = Crypto.deriveContentEncryptionKey(fmk);
    }

    /**
     * Prepare Envelope for encryption. For CDOC single file master key (FMK) is generated. For each recipient FMK is
     * encrypted with generated key that single recipient can decrypt with their private key.
     * @param recipients encryption key material either with public key or symmetric key and key label. After
     *          {@link #prepare(List, KeyCapsuleClient)} has returned, it is safe to call
     *          {@link EncryptionKeyMaterial#destroy()} to clean up secret key material (it will not be referenced
     *          anymore).
     *
     * @param capsuleClient if capsuleClient is provided then store generated ephemeral key material in the server
     * @return Envelope that has key material prepared and can be used for
     *          {@link #encrypt(List, OutputStream) encryption}
     * @throws GeneralSecurityException
     * @throws ExtApiException if communication with capsuleClient to store ephemeral key material fails
     */
    public static Envelope prepare(List<EncryptionKeyMaterial> recipients, @Nullable KeyCapsuleClient capsuleClient)
             throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(recipients);

        byte[] fmk = Crypto.generateFileMasterKey();
        return new Envelope(RecipientFactory.buildRecipients(fmk, recipients, capsuleClient), fmk);
    }

    /**
     * Read envelope header until HMAC start and return FlatBuffers header
     * @param envelopeIs input stream that contain CDOC
     * @return byte array containing FlatBuffers header
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if a CDOC parsing error has occurred
     */
    static byte[] readFBSHeader(InputStream envelopeIs) throws IOException, CDocParseException {
        if (envelopeIs.available() < MIN_ENVELOPE_SIZE) {
            throw new CDocParseException("not enough bytes to read, expected min of " + MIN_ENVELOPE_SIZE);
        }

        if (!Arrays.equals(PRELUDE, envelopeIs.readNBytes(PRELUDE.length))) {
            throw new CDocParseException("stream is not CDOC");
        }

        byte version = (byte) envelopeIs.read();
        if (VERSION != version) {
            throw new CDocParseException("Unsupported CDOC version " + version);
        }

        ByteBuffer headerLenBuf = ByteBuffer.wrap(envelopeIs.readNBytes(Integer.BYTES));
        headerLenBuf.order(ByteOrder.BIG_ENDIAN);
        int headerLen = headerLenBuf.getInt();

        if ((envelopeIs.available() < headerLen + Crypto.HHK_LEN_BYTES)
                || (headerLen < MIN_HEADER_LEN) || (headerLen > MAX_HEADER_LEN))  {
            throw new CDocParseException("invalid CDOC header length: " + headerLen);
        }

        return envelopeIs.readNBytes(headerLen);
    }

    /**
     * Parse header section from CDOC2.
     * @param envelopeIs InputStream that contains CDOC2 file (envelope)
     * @return list of recipients parsed from Header
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if parsing CDOC Envelope has failed
     * @throws GeneralSecurityException if decoding cryptographic keys from FlatBuffers RecipientRecord has failed
     */
    public static List<Recipient> parseHeader(InputStream envelopeIs)
            throws IOException, CDocParseException, GeneralSecurityException {

        byte[] fbsHeaderBytes = readFBSHeader(envelopeIs);
        Header header = deserializeFBSHeader(fbsHeaderBytes);
        return getRecipients(header);
    }

    private static List<Recipient> getRecipients(Header header) throws CDocParseException, GeneralSecurityException {

        List<Recipient> recipientList = new LinkedList<>();
        for (int i = 0; i < header.recipientsLength(); i++) {
            RecipientRecord r = header.recipients(i);

            try {
                recipientList.add(RecipientDeserializer.deserialize(r));
            } catch (UnknownFlatBufferTypeException e) { //ignore unknown recipients
                log.warn("Unknown Capsule type {}. Ignoring.", r.capsuleType());
            }
        }
        return recipientList;
    }

    /**
     * Deserialize FlatBuffers header
     * @param buf buffer containing FlatBuffers header
     * @return parsed FlatBuffers {@link Header}
     */
    static Header deserializeFBSHeader(byte[] buf) {
        Objects.requireNonNull(buf);
        ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
        return Header.getRootAsHeader(byteBuffer);
    }

    /**Get additional data used to initialize ChaChaCipher AAD*/
    public static byte[] getAdditionalData(byte[] header, byte[] headerHMAC) {
        Objects.requireNonNull(header);
        Objects.requireNonNull(headerHMAC);
        final byte[] cDoc20Payload = "CDOC20payload".getBytes(StandardCharsets.UTF_8);
        ByteBuffer bb = ByteBuffer.allocate(cDoc20Payload.length + header.length + headerHMAC.length);
        bb.put(cDoc20Payload);
        bb.put(header);
        bb.put(headerHMAC);
        return bb.array();
    }

    /**
     * Encrypt payloadFiles. Create CDOC2 container and write it to OutputStream.
     * @param payloadFiles files to be encrypted and added to the container
     * @param os OutputStream to write CDOC2 container
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void encrypt(List<File> payloadFiles, OutputStream os) throws IOException, GeneralSecurityException {
        log.trace("encrypt");
        os.write(PRELUDE);
        os.write(new byte[]{VERSION});

        byte[] headerBytes = serializeHeader();

        ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putInt(headerBytes.length);
        byte[] headerLenBytes = bb.array();

        os.write(headerLenBytes);
        os.write(headerBytes);

        byte[] hmac = Crypto.calcHmacSha256(hmacKey, headerBytes);
        os.write(hmac);
        byte[] additionalData = getAdditionalData(headerBytes, hmac);
        try (CipherOutputStream cipherOutputStream =
                     ChaChaCipher.initChaChaOutputStream(os, cekKey, additionalData)) {

            Tar.archiveFiles(cipherOutputStream, payloadFiles);
        }
    }

    /**
     * Decrypt CDOC2 container, read from cdocInputStream.
     * @param cdocInputStream contains CDOC2 container
     * @param keyMaterial decryption key material
     * @param extract if true, extract files to outputDir. Otherwise, decrypt and list valid CDOC2 contents
     *                that can be decrypted
     * @param outputDir output directory where decrypted files are extracted when extract=true
     * @param filesToExtract if not null, extract specified files otherwise all files.
     *                       No effect for list (extract=false)
     * @param capsulesClientFac configured key servers clients factory.
     * @return list of files decrypted and written into outputDir, when extract = true
     *          or list of extractable files found from CDOC2 container when extract = false
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if cdocInputStream is in invalid format and can not be parsed
     * @throws ExtApiException if error happened when communicating with key server
     */
    private static List<ArchiveEntry> decrypt(InputStream cdocInputStream,
                                              DecryptionKeyMaterial keyMaterial,
                                              boolean extract,
                                              @Nullable Path outputDir,
                                              @Nullable List<String> filesToExtract,
                                              @Nullable KeyCapsuleClientFactory capsulesClientFac)
            throws GeneralSecurityException, IOException, CDocException {

        byte[] fbsHeaderBytes = readFBSHeader(cdocInputStream);
        byte[] hmac = readHmac(cdocInputStream);
        Header header = deserializeFBSHeader(fbsHeaderBytes);
        List<Recipient> recipients = getRecipients(header);

        for (Recipient recipient : recipients) {
            if (recipient.getRecipientId().equals(keyMaterial.getRecipientId())) {
                byte[] kek = recipient.deriveKek(keyMaterial, capsulesClientFac);
                byte[] fmk;
                if (recipient.getFmkEncryptionMethod() == FMK_ENC_METHOD_BYTE) {
                    fmk = Crypto.xor(kek, recipient.getEncryptedFileMasterKey());
                } else {
                    throw new CDocParseException("Unknown FMK encryption method: "
                            + recipient.getFmkEncryptionMethod());
                }

                SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
                SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);

                checkHmac(hmac, fbsHeaderBytes, hmacKey);

                log.debug("payload available (at least) {}", cdocInputStream.available());

                if (header.payloadEncryptionMethod() == PayloadEncryptionMethod.CHACHA20POLY1305) {
                    byte[] additionalData = getAdditionalData(fbsHeaderBytes, hmac);
                    try (CipherInputStream cis =
                                 ChaChaCipher.initChaChaInputStream(cdocInputStream, cekKey, additionalData)) {

                        return Tar.processTarGz(cis, outputDir, filesToExtract, extract);
                    }
                } else {
                    throw new CDocParseException("Unknown payload encryption method "
                            + header.payloadEncryptionMethod());
                }
            }
        }

        log.error("Recipient {} not present in CDOC. Cannot decrypt CDOC.", keyMaterial.getRecipientId());
        throw new CDocParseException("Recipient " + keyMaterial.getRecipientId() + " not found, cannot decrypt");
    }

    /**
     * Check that hmac read from cdocInputStream and hmac calculated from headerBytes match
     * @param hmac read from CDOC
     * @param headerBytes header bytes
     * @param hmacKey header HMAC key, derived from FMK
     * @throws GeneralSecurityException  if security/crypto error has occurred
     * @throws CDocParseException if calculated HMAC doesn't match with HMAC in header
     */
    private static void checkHmac(byte[] hmac, byte[] headerBytes, SecretKey hmacKey)
            throws GeneralSecurityException, CDocParseException {

        Objects.requireNonNull(hmac);
        Objects.requireNonNull(headerBytes);

        byte[] calculatedHmac = Crypto.calcHmacSha256(hmacKey, headerBytes);

        if (!Arrays.equals(calculatedHmac, hmac)) {
            if (log.isDebugEnabled()) {
                log.debug("calc hmac: {}", HexFormat.of().formatHex(calculatedHmac));
                log.debug("file hmac: {}", HexFormat.of().formatHex(hmac));
            }
            throw new CDocParseException("Invalid hmac");
        }
    }

    private static byte[] readHmac(InputStream cdocInputStream) throws IOException, CDocParseException {
        if (cdocInputStream.available() > Crypto.HHK_LEN_BYTES) {
            return cdocInputStream.readNBytes(Crypto.HHK_LEN_BYTES);
        } else {
            throw new CDocParseException("No hmac");
        }
    }

    /**
     * Decrypt CDOC2 container, read from cdocInputStream.
     * @param cdocInputStream contains CDOC2 container
     * @param recipientKeyMaterial decryption key material
     * @param outputDir output directory where decrypted files are decrypted
     * @param keyServerClientFac configured key servers clients factory.
     * @return list of files decrypted and written into outputDir
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if cdocInputStream is invalid format
     * @throws ExtApiException if error happened when communicating with key server
     */
    public static List<String> decrypt(InputStream cdocInputStream, DecryptionKeyMaterial recipientKeyMaterial,
                                       Path outputDir, @Nullable KeyCapsuleClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocException {
        return decrypt(cdocInputStream, recipientKeyMaterial, true, outputDir, null,
                keyServerClientFac).stream()
                    .map(ArchiveEntry::getName)
                    .toList();
    }

    /**
     * Decrypt CDOC2 container, read from cdocInputStream.
     * @param cdocInputStream contains CDOC2 container
     * @param recipientKeyMaterial decryption key material
     * @param outputDir output directory where decrypted files are decrypted
     * @param filesToExtract if not null, extract specified files otherwise all files.
     * @param keyServerClientFac configured key servers clients factory.
     * @return list of files decrypted and written into outputDir
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if cdocInputStream is invalid format
     * @throws ExtApiException if error happened when communicating with key server
     */
    public static List<String> decrypt(InputStream cdocInputStream, DecryptionKeyMaterial recipientKeyMaterial,
                                       Path outputDir, @Nullable List<String> filesToExtract,
                                       @Nullable KeyCapsuleClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocException {

        return decrypt(cdocInputStream, recipientKeyMaterial, true, outputDir, filesToExtract, keyServerClientFac)
                .stream()
                .map(ArchiveEntry::getName)
                .toList();
    }

    public static List<ArchiveEntry> list(InputStream cdocInputStream, DecryptionKeyMaterial recipientKeyMaterial,
                                          @Nullable KeyCapsuleClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocException {
        return decrypt(cdocInputStream, recipientKeyMaterial, false, null, null, keyServerClientFac);
    }

    byte[] serializeHeader() {
        return serializeHeader(this.recipients);
    }

    static byte[] serializeHeader(Recipient[] recipients) {
        Objects.requireNonNull(recipients);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        FlatBufferBuilder builder = new FlatBufferBuilder(1024);
        int[] recipientOffsets = new int[recipients.length];

        for (int i = 0; i < recipients.length; i++) {
            recipientOffsets[i] = recipients[i].serialize(builder);
        }

        int recipientsVector = Header.createRecipientsVector(builder, recipientOffsets);

        Header.startHeader(builder);
        Header.addRecipients(builder, recipientsVector);
        Header.addPayloadEncryptionMethod(builder, PAYLOAD_ENC_BYTE);
        int headerOffset = Header.endHeader(builder);
        Header.finishHeaderBuffer(builder, headerOffset);

        ByteBuffer buf = builder.dataBuffer();
        int bufLen = buf.limit() - buf.position();
        if (bufLen > MAX_HEADER_LEN) {
            log.error("Header serialization failed. Header len {} exceeds MAX_HEADER_LEN {}", bufLen, MAX_HEADER_LEN);
            throw new IllegalStateException("Header serialization failed. Header length " + bufLen
                    + " exceeds max header length " + MAX_HEADER_LEN);
        }
        os.write(buf.array(), buf.position(), bufLen);
        return os.toByteArray();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Envelope envelope = (Envelope) o;
        return Arrays.equals(recipients, envelope.recipients)
                && Objects.equals(hmacKey, envelope.hmacKey)
                && Objects.equals(cekKey, envelope.cekKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(hmacKey, cekKey);
        result = 31 * result + Arrays.hashCode(recipients);
        return result;
    }


}
