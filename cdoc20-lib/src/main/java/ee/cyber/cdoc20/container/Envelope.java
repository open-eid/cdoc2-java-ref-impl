package ee.cyber.cdoc20.container;

import com.google.flatbuffers.FlatBufferBuilder;

import ee.cyber.cdoc20.container.recipients.EccPubKeyRecipient;
import ee.cyber.cdoc20.container.recipients.EccRecipient;
import ee.cyber.cdoc20.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc20.crypto.ChaChaCipher;
import ee.cyber.cdoc20.crypto.Crypto;

import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.Header;
import ee.cyber.cdoc20.fbs.header.PayloadEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.RecipientRecord;
import ee.cyber.cdoc20.fbs.recipients.ECCKeyServer;
import ee.cyber.cdoc20.fbs.recipients.ECCPublicKey;
import ee.cyber.cdoc20.util.KeyServerClient;
import ee.cyber.cdoc20.util.KeyServerClientFactory;
import ee.cyber.cdoc20.util.ExtApiException;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.*;

import static ee.cyber.cdoc20.fbs.header.Details.*;

@SuppressWarnings("checkstyle:FinalClass")
public class Envelope {
    private static final Logger log = LoggerFactory.getLogger(Envelope.class);

    protected static final byte[] PRELUDE = {'C', 'D', 'O', 'C'};
    public static final byte VERSION = 2;
    public static final int MIN_HEADER_LEN = 246; //TODO: find size with FBS overhead

    // MIN_HEADER_LEN value:
    // raw lengths in bytes (without FBS overhead) for  single ECCPublicKey recipient:

    // details_type: 1
    // details ECCPublicKey recipient:
    //   curve: 1
    //   sender_public_key: 97
    //   receiver_public_key:97
    // encrypted_fmk: 48 //secp384r1 curve
    // fmk_encryption_method: 1
    //
    // per header:
    // payload_encryption_method: 1
    //
    // in practice ECCPublicKey in fbs ~284bytes


    public static final int MIN_PAYLOAD_LEN = 1; //TODO: find minimal payload size


    public static final int MAX_HEADER_LEN = 1024 * 1024; //1MB

    /**Minimal valid envelope size in bytes*/
    public static final int MIN_ENVELOPE_SIZE = PRELUDE.length
            + Byte.BYTES //version 0x02
            + Integer.BYTES //header length field
            + MIN_HEADER_LEN
            + Crypto.HHK_LEN_BYTES
            + MIN_PAYLOAD_LEN;

    private static final byte PAYLOAD_ENC_BYTE = PayloadEncryptionMethod.CHACHA20POLY1305;
    private final EccRecipient[] eccRecipients;
    private final KeyServerClient keyServerClient;
    private final SecretKey hmacKey;
    private final SecretKey cekKey;

    private Envelope(EccRecipient[] recipients, byte[] fmk, KeyServerClient keyServerClient) {
        this.eccRecipients = recipients;
        this.keyServerClient = keyServerClient;
        this.hmacKey = Crypto.deriveHeaderHmacKey(fmk);
        this.cekKey = Crypto.deriveContentEncryptionKey(fmk);
    }

    private Envelope(EccRecipient[] recipients, byte[] fmk) {
        this(recipients, fmk, null);
    }



    /**
     * Prepare Envelope for ECPublicKey recipients. For each recipient, sender key pair is generated. Single generated
     * File Master Key (FMK) is used for all recipients and encrypted with recipient public key and generated sender
     * private key.
     * @param recipients list of recipients public keys
     * @return Envelope ready for payload
     * @throws InvalidKeyException if recipient key is not suitable
     * @throws GeneralSecurityException if other crypto related exceptions happen
     */
    public static Envelope prepare(List<ECPublicKey> recipients) throws GeneralSecurityException {
        try {
            return prepare(recipients, null);
        } catch (ExtApiException e) { // prepare without keyServer should not throw ApiException
            log.error("Unexpected ApiException", e);
            throw new IllegalStateException("Unexpected ApiException", e);
        }
    }

    public static Envelope prepare(List<ECPublicKey> recipients, KeyServerClient keyServerClient)
            throws GeneralSecurityException, ExtApiException {
        log.debug("Preparing envelope for {} recipient(s)", recipients.size());
        byte[] fmk = Crypto.generateFileMasterKey();
        if (keyServerClient == null) {
            return new Envelope(buildEccRecipients(fmk, recipients), fmk);
        } else {
            return new Envelope(buildEccServerRecipients(fmk, recipients, keyServerClient), fmk, keyServerClient);
        }
    }

    static List<EccRecipient> parseHeader(InputStream envelopeIs, ByteArrayOutputStream outHeaderOs)
            throws IOException, CDocParseException, GeneralSecurityException {

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
        Header header = deserializeHeader(headerBytes);

        return getDetailsEccRecipients(header);
    }

    private static List<EccRecipient> getDetailsEccRecipients(Header header)
            throws CDocParseException, GeneralSecurityException {

        List<EccRecipient> eccRecipientList = new LinkedList<>();
        for (int i = 0; i < header.recipientsLength(); i++) {
            RecipientRecord r = header.recipients(i);

            if (FMKEncryptionMethod.XOR != r.fmkEncryptionMethod()) {
                throw new CDocParseException("invalid FMK encryption method: " + r.fmkEncryptionMethod());
            }

            if (r.encryptedFmkLength() != Crypto.FMK_LEN_BYTES) {
                throw new CDocParseException("invalid FMK len: " + r.encryptedFmkLength());
            }

            ByteBuffer encryptedFmkBuf = r.encryptedFmkAsByteBuffer();
            byte[] encryptedFmkBytes = Arrays.copyOfRange(encryptedFmkBuf.array(),
                    encryptedFmkBuf.position(), encryptedFmkBuf.limit());

            if (r.detailsType() == recipients_ECCPublicKey) {
                ECCPublicKey detailsEccPublicKey = (ECCPublicKey) r.details(new ECCPublicKey());
                if (detailsEccPublicKey == null) {
                    throw new CDocParseException("error parsing Details");
                }

                try {
                    EllipticCurve curve = EllipticCurve.forValue(detailsEccPublicKey.curve());
                    ECPublicKey recipientPubKey =
                            curve.decodeFromTls(detailsEccPublicKey.recipientPublicKeyAsByteBuffer());
                    ECPublicKey senderPubKey =
                            curve.decodeFromTls(detailsEccPublicKey.senderPublicKeyAsByteBuffer());

                    eccRecipientList.add(new EccPubKeyRecipient(curve, recipientPubKey, senderPubKey,
                            encryptedFmkBytes));
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new CDocParseException("illegal EC pub key encoding", illegalArgumentException);
                }
            } else if (r.detailsType() == recipients_ECCKeyServer) {
                ECCKeyServer detailsEccKeyServer = (ECCKeyServer) r.details(new ECCKeyServer());
                if (detailsEccKeyServer == null) {
                    throw new CDocParseException("error parsing Details.ECCKeyServer");
                }

                try {
                    EllipticCurve curve = EllipticCurve.forValue(detailsEccKeyServer.curve());
                    ECPublicKey recipientPubKey =
                            curve.decodeFromTls(detailsEccKeyServer.recipientPublicKeyAsByteBuffer());
                    String keyServerId = detailsEccKeyServer.keyserverId();
                    String transactionId = detailsEccKeyServer.transactionId();

                    eccRecipientList.add(new EccServerKeyRecipient(curve, recipientPubKey, keyServerId,
                            transactionId, encryptedFmkBytes));

                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new CDocParseException("illegal EC pub key encoding", illegalArgumentException);
                }

            } else {
                log.warn("Unknown Details type {}. Ignoring.", r.detailsType());
            }
        }
        return eccRecipientList;
    }

    static Header deserializeHeader(byte[] buf) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(buf);
        return Header.getRootAsHeader(byteBuffer);
    }

    /**Get additional data used to initialize ChaChaCipher AAD*/
    public static byte[] getAdditionalData(byte[] header, byte[] headerHMAC) {
        final byte[] cDoc20Payload = "CDOC20payload".getBytes(StandardCharsets.UTF_8);
        ByteBuffer bb = ByteBuffer.allocate(cDoc20Payload.length + header.length + headerHMAC.length);
        bb.put(cDoc20Payload);
        bb.put(header);
        bb.put(headerHMAC);
        return bb.array();
    }

    /**
     * @param curve EC curve that sender and recipient must use
     * @param senderEcKeyPair sender EC key pair, must have EC curve specified in curve
     * @param recipientPubKey recipient EC public key, must have EC curve specified in curve
     * @param fmk plain file master key (not encrypted)
     * @return EccRecipient with sender and recipient public key and fmk encrypted with sender private
     *         and recipient public key
     * @throws GeneralSecurityException if security/crypto exception happens
     */
    private static EccPubKeyRecipient buildEccRecipient(EllipticCurve curve, KeyPair senderEcKeyPair,
                                                        ECPublicKey recipientPubKey, byte[] fmk)
            throws GeneralSecurityException {

        byte[] kek = Crypto.deriveKeyEncryptionKey(senderEcKeyPair, recipientPubKey, Crypto.CEK_LEN_BYTES);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        return new EccPubKeyRecipient(
                curve, recipientPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk);
    }

    /**
     * Generate sender key pair for each recipient. Encrypt fmk with KEK derived from generated sender private key
     * and recipient public key
     * @param fmk file master key (plain)
     * @param recipients  list of recipients public keys
     * @return For each recipient create EccRecipient with generated sender and recipient public key and
     *          fmk encrypted with sender private and recipient public key
     * @throws InvalidKeyException if recipient key is not suitable
     * @throws GeneralSecurityException if other crypto related exceptions happen
     */
    private static EccPubKeyRecipient[] buildEccRecipients(byte[] fmk, List<ECPublicKey> recipients)
            throws InvalidKeyException, GeneralSecurityException {

        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException("Invalid FMK len");
        }

        List<EccPubKeyRecipient> result = new ArrayList<>(recipients.size());
        for (ECPublicKey recipientPubKey : recipients) {
            String oid = ECKeys.getCurveOid(recipientPubKey);
            EllipticCurve curve;
            try {
                curve = EllipticCurve.forOid(oid);
            } catch (NoSuchAlgorithmException nsae) {
                String x509encoded = Base64.getEncoder().encodeToString(recipientPubKey.getEncoded());
                log.error("Invalid recipient key: {}, EC curve {} not supported", x509encoded, oid);
                throw new InvalidKeyException("Unsupported EC curve oid " + oid);
            }

            if (!curve.isValidKey(recipientPubKey)) {
                String x509encoded = Base64.getEncoder().encodeToString(recipientPubKey.getEncoded());
                log.error("Invalid recipient key: {}, key not valid for {}", x509encoded, curve.getName());
                throw new InvalidKeyException("Key not valid for " + curve.getName());
            }

            KeyPair senderEcKeyPair = curve.generateEcKeyPair();
            EccPubKeyRecipient eccRecipient = buildEccRecipient(curve, senderEcKeyPair, recipientPubKey, fmk);
            result.add(eccRecipient);
        }

        return result.toArray(new EccPubKeyRecipient[0]);
    }

    /**
     * Fill EccServerKeyRecipient POJO, so that they are ready to be serialized into CDOC header. Calls
     * {@link #buildEccRecipients(byte[], List)} to generate sender key pair and encrypt FMK. Stores sender public key
     * in key server and gets corresponding transactionId from server.
     * @param fmk file master key (plain)
     * @param recipients  list of recipients public keys
     * @param keyServerClient used to store sender public key and get transactionId
     * @return For each recipient create EccServerKeyRecipient with fields filled
     */
     private static EccServerKeyRecipient[] buildEccServerRecipients(
            byte[] fmk, List<ECPublicKey> recipients, KeyServerClient keyServerClient)
                throws GeneralSecurityException, ExtApiException {

        List<EccServerKeyRecipient> result = new LinkedList<>();
        EccPubKeyRecipient[] eccRecipients = buildEccRecipients(fmk, recipients);

        for (EccPubKeyRecipient eccRec: eccRecipients) {
            String transactionId =
                    keyServerClient.storeSenderKey(eccRec.getRecipientPubKey(), eccRec.getSenderPubKey());
            String serverId = keyServerClient.getServerIdentifier();
            result.add(new EccServerKeyRecipient(eccRec.getEllipticCurve(),
                    eccRec.getRecipientPubKey(), serverId, transactionId, eccRec.getEncryptedFileMasterKey()));
        }

        return result.toArray(new EccServerKeyRecipient[0]);
    }

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

            //hidden feature, mainly for testing
            if (System.getProperties().containsKey("ee.cyber.cdoc20.disableCompression")
                    && (payloadFiles.size() == 1)
                    && (payloadFiles.get(0).getName().endsWith(".tgz")
                        || payloadFiles.get(0).getName().endsWith(".tar.gz"))) {

                    log.warn("disableCompression=true; Encrypting {} contents without compression",
                            payloadFiles.get(0));
                    try (FileInputStream fis = new FileInputStream(payloadFiles.get(0))) {
                        fis.transferTo(cipherOutputStream);
                    }
                    return;
            }
            Tar.archiveFiles(cipherOutputStream, payloadFiles);
        }
    }

    private static List<ArchiveEntry> decrypt(InputStream cdocInputStream, KeyPair recipientEcKeyPair,
                                              Path outputDir, List<String> filesToExtract, boolean extract,
                                              KeyServerClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocParseException, ExtApiException {

        log.trace("Envelope::decrypt");
        log.debug("total available {}", cdocInputStream.available());

        ECPublicKey recipientPubKey = (ECPublicKey) recipientEcKeyPair.getPublic();
        if (log.isInfoEnabled()) {
            log.info("Finding encrypted FMK for pub key {}",
                    HexFormat.of().formatHex(ECKeys.encodeEcPubKeyForTls(recipientPubKey)));
        }

        ByteArrayOutputStream fileHeaderOs = new ByteArrayOutputStream();
        List<EccRecipient> details = parseHeader(cdocInputStream, fileHeaderOs);

        for (EccRecipient detailsEccRecipient : details) {

            if (recipientPubKey.equals(detailsEccRecipient.getRecipientPubKey())) {
                ECPublicKey senderPubKey;
                if (detailsEccRecipient instanceof EccPubKeyRecipient) {
                    senderPubKey = ((EccPubKeyRecipient) detailsEccRecipient).getSenderPubKey();
                } else if (detailsEccRecipient instanceof EccServerKeyRecipient) {

                    EccServerKeyRecipient eccServerKeyRecipient =
                            (EccServerKeyRecipient) detailsEccRecipient;

                    String transactionId = eccServerKeyRecipient.getTransactionId();
                    if (transactionId == null) {
                        log.error("No transactionId for recipient {}",
                                HexFormat.of().formatHex(ECKeys.encodeEcPubKeyForTls(recipientPubKey)));
                        throw new CDocParseException("TransactionId missing in record");
                    }

                    String serverId = eccServerKeyRecipient.getKeyServerId();
                    if (serverId == null) {
                        log.error("No serverId for recipient {}",
                                HexFormat.of().formatHex(ECKeys.encodeEcPubKeyForTls(recipientPubKey)));
                        throw new CDocParseException("ServerId missing in record");
                    }

                    if ((keyServerClientFac == null) || keyServerClientFac.getForId(serverId) == null) {
                        log.error("Configuration not found for server {}", serverId);
                        throw new CDocParseException("Configuration not found for server \"" + serverId + "\"");
                    }

                    try {
                        KeyServerClient keyServerClient = keyServerClientFac.getForId(serverId);
                        Optional<ECPublicKey> senderPubKeyOptional = keyServerClient.getSenderKey(transactionId);
                        senderPubKey = senderPubKeyOptional.orElseThrow();
                    } catch (NoSuchElementException nse) {
                        log.info("Key not found for id {} from {}", transactionId, serverId);
                        throw new ExtApiException("Sender key not found for " + transactionId);
                    } catch (ExtApiException apiException) {
                        log.error("Error querying {} for {} ({})", serverId, transactionId, apiException);
                        throw apiException;
                    }

                } else {
                    throw new CDocParseException("Unknown Details.EccRecipient type " + detailsEccRecipient);
                }

                byte[] kek = Crypto.deriveKeyDecryptionKey(recipientEcKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
                byte[] fmk = Crypto.xor(kek, detailsEccRecipient.getEncryptedFileMasterKey());

                SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
                SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);

                byte[] hmac = checkHmac(cdocInputStream, fileHeaderOs.toByteArray(), hmacKey);

                log.debug("payload available {}", cdocInputStream.available());

                byte[] additionalData = getAdditionalData(fileHeaderOs.toByteArray(), hmac);
                try (CipherInputStream cis =
                             ChaChaCipher.initChaChaInputStream(cdocInputStream, cekKey, additionalData)) {

                    //hidden feature, mainly for testing
                    if (System.getProperties().containsKey("ee.cyber.cdoc20.disableCompression")
                            && System.getProperties().containsKey("ee.cyber.cdoc20.cDocFile")) {
                        log.warn("disableCompression=true; Decrypting only without decompressing");
                        return decryptTarGZip(outputDir, cis);
                    }

                    return Tar.processTarGz(cis, outputDir, filesToExtract, extract);
                }
            }
        }

        log.info("No matching EC pub key found");
        throw new CDocParseException("No matching EC pub key found");
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

    /* Decrypt contents of cis and copy its contents into .tgz file under outputDir*/
    @SuppressWarnings("java:S106")
    private static List<ArchiveEntry> decryptTarGZip(Path outputDir, CipherInputStream cis) throws IOException {

        String cDocFileName = System.getProperty("ee.cyber.cdoc20.cDocFile");
        if ((cDocFileName == null) || cDocFileName.isEmpty()) {
            throw new IllegalStateException("Property \"ee.cyber.cdoc20.cDocFile\" not defined.");
        }

        if (cDocFileName.endsWith(".cdoc")) {
            cDocFileName = cDocFileName.substring(0, cDocFileName.length() - ".cdoc".length());
        }

        File tarGzFile = outputDir.resolve(cDocFileName + ".tgz").toFile();
        log.debug("Decrypting {} to {}", cDocFileName, tarGzFile);
        try (FileOutputStream fos = new FileOutputStream(tarGzFile)) {
            long transferred = 0;
            byte[] buffer = new byte[8192];
            int read;
            int megaBytes = 0;
            while ((read = cis.read(buffer, 0, 8192)) >= 0) {
                fos.write(buffer, 0, read);
                transferred += read;
                if ((transferred > (megaBytes + 1) * (1024 * 1024))) {
                    megaBytes += 1;
                    if ((megaBytes % 10) == 0) {
                        System.out.print("*");
                    } else {
                        System.out.print(".");
                    }
                    if ((megaBytes % 100) == 0) {
                        System.out.println(" " + megaBytes);
                    }

                    System.out.flush();
                }
            }

            final long fileSize = transferred;

            //CHECKSTYLE:OFF
            return List.of(new ArchiveEntry() {
                @Override
                public String getName() { return tarGzFile.getName(); }

                @Override
                public long getSize() { return fileSize; }

                @Override
                public boolean isDirectory() { return false; }

                @Override
                public Date getLastModifiedDate() {return Date.from(Instant.now()); }
            });
            //CHECKSTYLE:ON
        }
    }

    /**
     * Decrypt and extract all files from cdocInputStream
     * @param cdocInputStream InputStream from where CDOC is read
     * @param recipientEcKeyPair decrypt CDOC using recipient EC key pair
     * @param outputDir extract decrypted files to output dir
     * @return file names extracted
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if cdocInputStream is invalid format
     */
    public static List<String> decrypt(InputStream cdocInputStream, KeyPair recipientEcKeyPair, Path outputDir)
            throws GeneralSecurityException, IOException, CDocParseException {

        try {
            return decrypt(cdocInputStream, recipientEcKeyPair, outputDir, null, true, null)
                    .stream()
                    .map(ArchiveEntry::getName)
                    .toList();
        } catch (ExtApiException e) { //ApiException should not be thrown if keyServerClientFac is null
            log.error("Unexpected ApiException {}", e.getMessage());
            throw new CDocParseException("Unexpected ApiException", e);
        }
    }
    /**
     * Decrypt and extract all files from cdocInputStream
     * @param cdocInputStream InputStream from where CDOC is read
     * @param recipientEcKeyPair decrypt CDOC using recipient EC key pair
     * @param outputDir extract decrypted files to output dir
     * @param keyServerClientFac key server client factory to create clients for serverId in cdocInputStream
     * @return file names extracted
     * @throws GeneralSecurityException if security/crypto error has occurred
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException if cdocInputStream is invalid format
     */
    public static List<String> decrypt(InputStream cdocInputStream, KeyPair recipientEcKeyPair, Path outputDir,
                                       KeyServerClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocParseException, ExtApiException {
        return decrypt(cdocInputStream, recipientEcKeyPair, outputDir, null, true, keyServerClientFac)
                .stream()
                .map(ArchiveEntry::getName)
                .toList();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Envelope envelope = (Envelope) o;
        return Arrays.equals(eccRecipients, envelope.eccRecipients)
                && Objects.equals(keyServerClient, envelope.keyServerClient)
                && Objects.equals(hmacKey, envelope.hmacKey)
                && Objects.equals(cekKey, envelope.cekKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(keyServerClient, hmacKey, cekKey);
        result = 31 * result + Arrays.hashCode(eccRecipients);
        return result;
    }

    public static List<String> decrypt(InputStream cdocInputStream, KeyPair recipientEcKeyPair, Path outputDir,
                                       List<String> filesToExtract, KeyServerClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocParseException, ExtApiException {

        return decrypt(cdocInputStream, recipientEcKeyPair, outputDir, filesToExtract, true, keyServerClientFac)
                .stream()
                .map(ArchiveEntry::getName)
                .toList();
    }


    public static List<ArchiveEntry> list(InputStream cdocInputStream, KeyPair recipientEcKeyPair,
                                          KeyServerClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocParseException, ExtApiException {
        return decrypt(cdocInputStream, recipientEcKeyPair, null, null, false, keyServerClientFac);
    }

    byte[] serializeHeader() throws IOException, NoSuchAlgorithmException {
        if (keyServerClient == null) {
            return serializeEccPubKeyHeader((EccPubKeyRecipient[]) this.eccRecipients);
        } else {
            return serializeEccServerRecipientsHeader((EccServerKeyRecipient[]) this.eccRecipients);
        }

    }

    static byte[] serializeEccPubKeyHeader(EccPubKeyRecipient[] eccRecipients) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        FlatBufferBuilder builder = new FlatBufferBuilder(1024);
        int[] recipients = new int[eccRecipients.length];

        for (int i = 0; i < eccRecipients.length; i++) {
            EccPubKeyRecipient eccRecipient = eccRecipients[i];

            int recipientPubKeyOffset = builder.createByteVector(eccRecipient.getRecipientPubKeyTlsEncoded());
            int senderPubKeyOffset = builder.createByteVector(eccRecipient.getSenderPubKeyTlsEncoded());
            int eccPubKeyOffset = ECCPublicKey.createECCPublicKey(builder,
                    eccRecipient.getEllipticCurve().getValue(),
                    recipientPubKeyOffset,
                    senderPubKeyOffset
            );

            int encFmkOffset =
                    RecipientRecord.createEncryptedFmkVector(builder, eccRecipient.getEncryptedFileMasterKey());

            RecipientRecord.startRecipientRecord(builder);
            RecipientRecord.addDetailsType(builder, recipients_ECCPublicKey);
            RecipientRecord.addDetails(builder, eccPubKeyOffset);

            RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
            RecipientRecord.addFmkEncryptionMethod(builder, FMKEncryptionMethod.XOR);

            int recipientOffset = RecipientRecord.endRecipientRecord(builder);

            recipients[i] = recipientOffset;
        }

        int recipientsOffset = Header.createRecipientsVector(builder, recipients);

        Header.startHeader(builder);
        Header.addRecipients(builder, recipientsOffset);
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

    static byte[] serializeEccServerRecipientsHeader(EccServerKeyRecipient[] eccServerRecipients) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        FlatBufferBuilder builder = new FlatBufferBuilder(1024);
        int[] recipients = new int[eccServerRecipients.length];

        for (int i = 0; i < eccServerRecipients.length; i++) {
            EccServerKeyRecipient eccServerRecipient = eccServerRecipients[i];

            int recipientPubKeyOffset = builder.createByteVector(eccServerRecipient.getRecipientPubKeyTlsEncoded());
            int keyServerOffset = builder.createString(eccServerRecipient.getKeyServerId());
            int transactionIdOffset = builder.createString(eccServerRecipient.getTransactionId());

            int detailsOffset = ECCKeyServer.createECCKeyServer(builder,
                    eccServerRecipient.getEllipticCurve().getValue(),
                    recipientPubKeyOffset,
                    keyServerOffset,
                    transactionIdOffset
                    );

            int encFmkOffset =
                    RecipientRecord.createEncryptedFmkVector(builder, eccServerRecipient.getEncryptedFileMasterKey());

            RecipientRecord.startRecipientRecord(builder);
            RecipientRecord.addDetailsType(builder, recipients_ECCKeyServer);
            RecipientRecord.addDetails(builder, detailsOffset);

            RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
            RecipientRecord.addFmkEncryptionMethod(builder, FMKEncryptionMethod.XOR);

            int recipientOffset = RecipientRecord.endRecipientRecord(builder);

            recipients[i] = recipientOffset;
        }
        int recipientsOffset = Header.createRecipientsVector(builder, recipients);

        Header.startHeader(builder);
        Header.addRecipients(builder, recipientsOffset);
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
        baos.write(buf.array(), buf.position(), bufLen);
        return baos.toByteArray();
    }
}
