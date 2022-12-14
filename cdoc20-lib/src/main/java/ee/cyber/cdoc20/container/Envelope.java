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
    private final KeyCapsuleClient capsuleClient;
    private final SecretKey hmacKey;
    private final SecretKey cekKey;

    private Envelope(Recipient[] recipients, byte[] fmk, @Nullable KeyCapsuleClient capsuleClient) {
        this.recipients = recipients;
        this.capsuleClient = capsuleClient;
        this.hmacKey = Crypto.deriveHeaderHmacKey(fmk);
        this.cekKey = Crypto.deriveContentEncryptionKey(fmk);
    }

    private Envelope(Recipient[] recipients, byte[] fmk) {

        this(recipients, fmk, null);
    }

    /**
     * Prepare Envelope for encryption. For CDOC single file master key (FMK) is generated. For each recipient FMK is
     * encrypted with generated key that single recipient can decrypt with their private key.
     * @param recipients encryption key material either with public key or symmetric key and key label
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
     * Parse flatbuffers {@link Header} from CDOC2
     * @param envelopeIs InputStream that contains CDOC2 file (envelope)
     * @param outHeaderOs if not null Header bytes will be written into outHeaderOs
     * @return FBS Header
     */
    static Header parseHeaderFBS(InputStream envelopeIs, @Nullable ByteArrayOutputStream outHeaderOs)
            throws IOException, CDocParseException {

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

        byte[] headerBytes = envelopeIs.readNBytes(headerLen);

        if (outHeaderOs != null) {
            outHeaderOs.writeBytes(headerBytes);
        }
        return deserializeHeader(headerBytes);
    }

    /**
     * Parse header section from CDOC2
     * @param envelopeIs InputStream that contains CDOC2 file (envelope)
     * @param outHeaderOs outHeaderOs if not null Header bytes will be written into outHeaderOs (for HMAC calculation)
     * @return list of recipients parsed from Header
     * @throws IOException
     * @throws CDocParseException
     * @throws GeneralSecurityException
     */
    public static List<Recipient> parseHeader(InputStream envelopeIs, @Nullable ByteArrayOutputStream outHeaderOs)
            throws IOException, CDocParseException, GeneralSecurityException {

        Header header = parseHeaderFBS(envelopeIs, outHeaderOs);
        if (header.payloadEncryptionMethod() != PayloadEncryptionMethod.CHACHA20POLY1305) {
            throw new CDocParseException("Unknown PayloadEncryptionMethod " + header.payloadEncryptionMethod());
        }
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

    static Header deserializeHeader(byte[] buf) {
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

        ByteArrayOutputStream fileHeaderOs = new ByteArrayOutputStream();
        List<Recipient> recipients = parseHeader(cdocInputStream, fileHeaderOs);

        for (Recipient recipient : recipients) {
            if (recipient.getRecipientId().equals(keyMaterial.getRecipientId())) {
                byte[] kek = recipient.deriveKek(keyMaterial, capsulesClientFac);
                byte[] fmk = Crypto.xor(kek, recipient.getEncryptedFileMasterKey());

                SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
                SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);

                byte[] hmac = checkHmac(cdocInputStream, fileHeaderOs.toByteArray(), hmacKey);

                log.debug("payload available (at least) {}", cdocInputStream.available());

                byte[] additionalData = getAdditionalData(fileHeaderOs.toByteArray(), hmac);
                try (CipherInputStream cis =
                             ChaChaCipher.initChaChaInputStream(cdocInputStream, cekKey, additionalData)) {

                    return Tar.processTarGz(cis, outputDir, filesToExtract, extract);
                }
            }
        }

        log.info("Recipient {} not present in CDOC. Can't decrypt CDOC.", keyMaterial.getRecipientId());
        throw new CDocParseException("Recipient " + keyMaterial.getRecipientId() + " not found, can't decrypt");
    }

    /**
     * Check that hmac read from cdocInputStream and hmac calculated from headerBytes match
     * @param cdocInputStream InputStream pointing to hmac
     * @param headerBytes header bytes
     * @param hmacKey header HMAC key, derived from FMK
     * @return hmac read from cdocInputStream
     * @throws IOException if an I/O error has occurred
     * @throws GeneralSecurityException  if security/crypto error has occurred
     * @throws CDocParseException if calculated HMAC doesn't match with HMAC in header
     */
    private static byte[] checkHmac(InputStream cdocInputStream, byte[] headerBytes, SecretKey hmacKey)
            throws IOException, GeneralSecurityException, CDocParseException {
        byte[] hmac;
        if (cdocInputStream.available() > Crypto.HHK_LEN_BYTES) {
            byte[] calculatedHmac = Crypto.calcHmacSha256(hmacKey, headerBytes);
            hmac = cdocInputStream.readNBytes(Crypto.HHK_LEN_BYTES);

            if (!Arrays.equals(calculatedHmac, hmac)) {
                if (log.isDebugEnabled()) {
                    log.debug("calc hmac: {}", HexFormat.of().formatHex(calculatedHmac));
                    log.debug("file hmac: {}", HexFormat.of().formatHex(hmac));
                }
                throw new CDocParseException("Invalid hmac");
            }
        } else {
            throw new CDocParseException("No hmac");
        }
        return hmac;
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
                && Objects.equals(capsuleClient, envelope.capsuleClient)
                && Objects.equals(hmacKey, envelope.hmacKey)
                && Objects.equals(cekKey, envelope.cekKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(capsuleClient, hmacKey, cekKey);
        result = 31 * result + Arrays.hashCode(recipients);
        return result;
    }


}
