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
import ee.cyber.cdoc20.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.keymaterial.EncryptionKeyMaterial;
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

import org.apache.commons.io.input.CountingInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public final class Envelope {

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
     *          {@link #prepare(List, KeyCapsuleClient)} has returned, it is safe
     *           to clean up secret key material (it will not be referenced
     *          anymore).
     *
     * @param capsuleClient if capsuleClient is provided then store generated ephemeral key material in the server
     * @return Envelope that has key material prepared and can be used for
     *          {@link #encrypt(List, OutputStream) encryption}
     * @throws GeneralSecurityException if fmk generation has failed
     * @throws ExtApiException if communication with capsuleClient to store ephemeral key material fails
     */
    public static Envelope prepare(
        List<EncryptionKeyMaterial> recipients,
        @Nullable KeyCapsuleClient capsuleClient
    ) throws GeneralSecurityException, ExtApiException {

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

    private static List<Recipient> getRecipients(Header header)
        throws CDocParseException, GeneralSecurityException {

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
     * @param os           OutputStream to write CDOC2 container
     * @throws IOException if an I/O error has occurred
     * @throws GeneralSecurityException if HMAC calculation or CipherOutputStream initialization
     *                                  has failed
     */
    public void encrypt(List<File> payloadFiles, OutputStream os)
        throws IOException, GeneralSecurityException {

        log.trace("encrypt");
        try (CipherOutputStream cipherOutputStream = prepareContainerForPayload(os)) {
            Tar.archiveFiles(cipherOutputStream, payloadFiles);
        }
    }

    /**
     * Re-encrypt CDOC. Decrypts input CDOC with decryptionKeyMaterial and copies files from it to
     * new CDOC that is encrypted with encryptionKeyMaterial. Temporary files are not created on
     * filesystem. For re-encryption only password and symmetric key are supported.
     * @param cdocInputStream contains CDOC2 container
     * @param decryptionKeyMaterial decryption key material
     * @param destReEncryptedCdoc [out] reEncrypted CDOC will be written into destReEncryptedCdoc
     * @param reEncryptionKeyMaterial reEncrypted CDOC will be encrypted with reEncryptionKeyMaterial.
     *                               Only password and symmetric key are supported for re-encryption
     * @param capsulesClientFac configured key servers clients factory used download decryption
     *                          key material. Not needed (null) when decryptionKeyMaterial is not in
     *                          key server.
     * @param destDir directory where re-encrypted CDOC will be written. Must exist and be writeable.
     *                Used to check available disk space. Null when destReEncryptedCdoc is not file
     *                based.
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error occurs
     * @throws CDocException if encryption/decryption error has occurred
     */
    public static void reEncrypt(
        InputStream cdocInputStream,
        DecryptionKeyMaterial decryptionKeyMaterial,
        OutputStream destReEncryptedCdoc,
        EncryptionKeyMaterial reEncryptionKeyMaterial,
        @Nullable Path destDir,
        @Nullable KeyCapsuleClientFactory capsulesClientFac
    ) throws GeneralSecurityException, IOException, CDocException {

        log.trace("reEncrypt");

        switch (reEncryptionKeyMaterial.getKeyOrigin()) {
            case SECRET, PASSWORD:
                break;
            default:
                // no technical reason not to support other key types (only password supported by long-term UC )
                throw new CDocException("Only password and symmetric key are supported for re-encryption.");
        }

        Envelope newContainer = Envelope.prepare(List.of(reEncryptionKeyMaterial), null);

        try (CipherOutputStream cipherOs = newContainer.prepareContainerForPayload(destReEncryptedCdoc);
            TarArchiveOutputStream transferToOs = Tar.createPosixTarZArchiveOutputStream(cipherOs)) {

            processContainer(cdocInputStream,
                decryptionKeyMaterial,
                new TranferToDelegate(transferToOs, destDir),
                capsulesClientFac);
        }
    }

    /**
     * Write CDOC header, HMAC to os and initialize cipher output stream for encryption.
     * Will use cekKey  created {@link Envelope#prepare(List, KeyCapsuleClient)}
     * @param os OutputStream to write CDOC2 container
     * @return CipherOutputStream constructed from CEK and os.
     *         Ready to write (encrypt) data. {@link CipherOutputStream#close()} must be called by caller.
     */
    private CipherOutputStream prepareContainerForPayload(OutputStream os)
        throws IOException, GeneralSecurityException {

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

        return ChaChaCipher.initChaChaOutputStream(os, cekKey, additionalData);
    }

    /**
     * Process (decrypt) CDOC2 container. Output depends on tarProcessingDelegate type.
     * @param cdocInputStream contains CDOC2 container
     * @param keyMaterial decryption key material
     * @param tarProcessingDelegate how to process tar (output could be extranct, transferto or list)
     * @param capsulesClientFac configured key servers clients factory for decryption
     * @return list of files decrypted and written into outputDir, when extract = true
     *          or list of extractable files found from CDOC2 container when extract = false
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if cdocInputStream is in invalid format and can not be parsed
     * @throws ExtApiException if error happened when communicating with key server
     */
    private static List<ArchiveEntry> processContainer(
        InputStream cdocInputStream,
        DecryptionKeyMaterial keyMaterial,
        TarEntryProcessingDelegate tarProcessingDelegate,
        @Nullable KeyCapsuleClientFactory capsulesClientFac
    ) throws GeneralSecurityException, IOException, CDocException {

        CountingInputStream containerIs = new CountingInputStream(cdocInputStream);
        byte[] fbsHeaderBytes = readFBSHeader(containerIs);
        byte[] hmac = readHmac(containerIs);
        Header header = deserializeFBSHeader(fbsHeaderBytes);
        List<Recipient> recipients = getRecipients(header);

        for (Recipient recipient : recipients) {
            if (recipient.getRecipientId().equals(keyMaterial.getRecipientId())) {
                byte[] kek = recipient.deriveKek(keyMaterial, capsulesClientFac);
                byte[] fmk = decryptRecipientFmk(recipient, kek);

                SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
                SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);

                checkHmac(hmac, fbsHeaderBytes, hmacKey);

                log.debug("Processed {} header bytes", containerIs.getByteCount());
                log.debug("payload available (at least) {}", containerIs.available());

                if (header.payloadEncryptionMethod() == PayloadEncryptionMethod.CHACHA20POLY1305) {
                    return processPayload(
                        containerIs, cekKey, getAdditionalData(fbsHeaderBytes, hmac), tarProcessingDelegate
                    );
                } else {
                    throw new CDocParseException("Unknown payload encryption method "
                        + header.payloadEncryptionMethod());
                }
            }
        }

        log.error("Recipient {} not present in CDOC. Cannot decrypt CDOC.", keyMaterial.getRecipientId());
        throw new CDocParseException("Recipient " + keyMaterial.getRecipientId() + " not found, cannot decrypt");
    }

    private static byte[] decryptRecipientFmk(Recipient recipient, byte[] keyEncryptionKey)
        throws CDocParseException {

        if (recipient.getFmkEncryptionMethod() == FMK_ENC_METHOD_BYTE) {
            return Crypto.xor(keyEncryptionKey, recipient.getEncryptedFileMasterKey());
        } else {
            throw new CDocParseException("Unknown FMK encryption method: "
                + recipient.getFmkEncryptionMethod());
        }
    }

    /**
     * Process payload (content).
     * @param containerIs InputStream containing CDOC2. InputStream position is just before payload.
     * @param cekKey content encryption key decrypted from header
     * @param additionalData used to initialize ChaChaCipher AAD
     * @param tarProcessingDelegate tar processing operation
     * @return archive entries processed
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error occurs
     */
    private static List<ArchiveEntry> processPayload(
        CountingInputStream containerIs,
        SecretKey cekKey,
        byte[] additionalData,
        TarEntryProcessingDelegate tarProcessingDelegate
    ) throws GeneralSecurityException, IOException {

        long headerSize = containerIs.getByteCount();
        List<ArchiveEntry> result;

        // lib must not report any exceptions before ChaCha Poly1305 mac is verified. Poly1305 MAC is
        // automatically verified, when all bytes were read from CipherInputStream
        try (CipherInputStream cis = ChaChaCipher.initChaChaInputStream(containerIs, cekKey, additionalData);
             TarDeflate tarDeflate = new TarDeflate(cis)) {

            try {
                result = tarDeflate.process(tarProcessingDelegate);
            } catch (Exception tarException) { // any exception from tar processing must not be
                                              // reported before Poly1305 MAC check has been performed
                // read remaining bytes to force Poly1305 MAC check
                // only report caught exception after ChaCha stream is drained and MAC checked
                long processedBytes = containerIs.getByteCount();
                drainStream(cis, null); //may throw IOException, tarException won't be re-thrown

                // since exception was thrown from TarDeflate, then created files are deleted by
                // TarDeflate::close() when exiting try with resources block
                if (containerIs.getByteCount() - processedBytes > 0) {
                    log.debug("Decrypted {} unprocessed bytes after \"{}\"",
                        containerIs.getByteCount() - processedBytes, tarException.toString());
                }

                throw tarException; //no exception from drainStream, re-throw original exception
            } finally {

                // read all bytes (if any) from ChaCha stream and check Poly1305 MAC
                // delete all created files when MAC check fails
                forcePoly1305MacCheck(containerIs, cis, tarDeflate::deleteCreatedFiles);
            }

        } finally  {
            log.debug("Processed {} bytes from payload (total CDOC2 {}B )",
                containerIs.getByteCount() - headerSize, containerIs.getByteCount());
        }
        return result;
    }

    /**
     * Read any remaining bytes from cipher input stream to force MAC check at the end of stream.
     * @param countingIs input stream
     * @param cis cipher input stream to drain
     * @param cleanUpFunc clean up function to run, when IOException happened during MAC check
     * @throws IOException if an I/O error occurs
     */
    private static void forcePoly1305MacCheck(
        CountingInputStream countingIs,
        CipherInputStream cis,
        @Nullable Runnable cleanUpFunc
    ) throws IOException {
        // deflate/tar stream processing is finished, drain any remaining bytes to force
        // ChaCha Poly1305 MAC check
        long processedBytes = countingIs.getByteCount();
        drainStream(cis, cleanUpFunc); //may throw IOException Poly1305 MAC check

        if (countingIs.getByteCount() - processedBytes > 0) {
            log.debug("Decrypted {} unprocessed bytes ",
                countingIs.getByteCount() - processedBytes);
        }
    }

    /**
     * Read all bytes from Cipher Input Stream
     * @param cis Cipher Input Stream to drain
     * @param cleanUpFunc clean up function to run, when IOException happened during draining
     * @throws IOException if an I/O error has occurred during draining
     */
    @SuppressWarnings("checkstyle:EmptyBlock")
    private static void drainStream(CipherInputStream cis, @Nullable Runnable cleanUpFunc)
        throws IOException {

        byte[] ignored = new byte[1024];
        try {
            while (cis.read(ignored) > 0) { }
        } catch (IOException drainingException) { // MAC check error is thrown as IOException
            if (cleanUpFunc != null) {
                cleanUpFunc.run();
            }
            throw drainingException;
        }
    }

    /**
     * Check that hmac read from cdocInputStream and hmac calculated from headerBytes match
     * @param hmac read from CDOC
     * @param headerBytes header bytes
     * @param hmacKey header HMAC key, derived from FMK
     * @throws GeneralSecurityException  if security/crypto error has occurred
     * @throws CDocParseException if calculated HMAC does not match with HMAC in header
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
    public static List<String> decrypt(
        InputStream cdocInputStream,
        DecryptionKeyMaterial recipientKeyMaterial,
        Path outputDir,
        @Nullable KeyCapsuleClientFactory keyServerClientFac
    ) throws GeneralSecurityException, IOException, CDocException {

        log.trace("decrypt");
        return processContainer(
            cdocInputStream,
            recipientKeyMaterial,
            new ExtractDelegate(outputDir, null),
            keyServerClientFac
        ).stream()
            .map(ArchiveEntry::getName)
            .toList();
    }

    /**
     * Decrypt CDOC2 container, read from cdocInputStream.
     * @param cdocInputStream contains CDOC2 container
     * @param recipientKeyMaterial decryption key material
     * @param outputDir output directory where decrypted files are decrypted
     * @param filesToExtract if not null, extract specified files otherwise all files.
     * @param keyServerClientFac configured key servers client factory.
     * @return list of files decrypted and written into outputDir
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if cdocInputStream is invalid format
     * @throws ExtApiException if error happened when communicating with key server
     */
    public static List<String> decrypt(
        InputStream cdocInputStream,
        DecryptionKeyMaterial recipientKeyMaterial,
        Path outputDir,
        @Nullable List<String> filesToExtract,
        @Nullable KeyCapsuleClientFactory keyServerClientFac
    ) throws GeneralSecurityException, IOException, CDocException {

        log.trace("decrypt");
        return processContainer(
            cdocInputStream,
            recipientKeyMaterial,
            new ExtractDelegate(outputDir, filesToExtract),
            keyServerClientFac
        ).stream()
            .map(ArchiveEntry::getName)
            .toList();
    }

    /**
     * List ArchiveEntries in CDOC
     * @param cdocInputStream contains CDOC2 container
     * @param recipientKeyMaterial decryption key material
     * @param keyServerClientFac configured key servers client factory.
     * @return List of ArchiveEntry decrypted from CDOC
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error occurs
     * @throws CDocException if encryption/decryption error has occurred
     */
    public static List<ArchiveEntry> list(InputStream cdocInputStream, DecryptionKeyMaterial recipientKeyMaterial,
                                          @Nullable KeyCapsuleClientFactory keyServerClientFac)
        throws GeneralSecurityException, IOException, CDocException {

        log.trace("list");
        return processContainer(
            cdocInputStream,
            recipientKeyMaterial,
            new ListDelegate(),
            keyServerClientFac
        );
    }

    /**
     * Serialize flatbuffer part (recipients data) of the header
     * @return serialized flatbuffer header
     */
    byte[] serializeHeader() {
        return serializeHeader(this.recipients);
    }

    /**
     * Serialize flatbuffer part (recipients data) of the header
     * @param recipients recipients to be serialized
     * @return serialized flatbuffer header
     */
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
