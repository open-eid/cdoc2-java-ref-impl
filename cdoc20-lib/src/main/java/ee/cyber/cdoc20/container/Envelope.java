package ee.cyber.cdoc20.container;

import com.google.flatbuffers.FlatBufferBuilder;

import ee.cyber.cdoc20.container.recipients.EccPubKeyRecipient;
import ee.cyber.cdoc20.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc20.container.recipients.RSAPubKeyRecipient;
import ee.cyber.cdoc20.container.recipients.RSAServerKeyRecipient;
import ee.cyber.cdoc20.container.recipients.Recipient;
import ee.cyber.cdoc20.crypto.ChaChaCipher;
import ee.cyber.cdoc20.crypto.Crypto;

import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;
import ee.cyber.cdoc20.crypto.RsaUtils;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.Header;
import ee.cyber.cdoc20.fbs.header.PayloadEncryptionMethod;
import ee.cyber.cdoc20.fbs.header.RecipientRecord;
import ee.cyber.cdoc20.fbs.recipients.ECCPublicKeyDetails;
import ee.cyber.cdoc20.fbs.recipients.KeyServerDetails;
import ee.cyber.cdoc20.fbs.recipients.RSAPublicKeyDetails;
import ee.cyber.cdoc20.fbs.recipients.ServerDetailsUnion;
import ee.cyber.cdoc20.fbs.recipients.ServerEccDetails;
import ee.cyber.cdoc20.fbs.recipients.ServerRsaDetails;
import ee.cyber.cdoc20.client.EcCapsuleClientImpl;
import ee.cyber.cdoc20.client.KeyCapsuleClient;
import ee.cyber.cdoc20.client.EcCapsuleClient;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.client.ExtApiException;
import ee.cyber.cdoc20.client.RsaCapsuleClient;
import ee.cyber.cdoc20.client.RsaCapsuleClientImpl;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidParameterSpecException;
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
    private final Recipient[] recipients;
    private final KeyCapsuleClient capsuleClient;
    private final SecretKey hmacKey;
    private final SecretKey cekKey;

    private Envelope(Recipient[] recipients, byte[] fmk, KeyCapsuleClient capsuleClient) {
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
     * @param recipients map<PublicKey, keyLabel> of supported PublicKey (required) paired to optional keyLabel string
     * @param capsuleClient if capsuleClient is provided then store generated key material in the server
     * @return Envelope that has key material prepared and can be used for
     *          {@link #encrypt(List, OutputStream) encryption}
     */
    public static Envelope prepare(Map<PublicKey, String> recipients, @Nullable KeyCapsuleClient capsuleClient)
            throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(recipients);
        byte[] fmk = Crypto.generateFileMasterKey();
        return new Envelope(buildRecipients(fmk, recipients, capsuleClient), fmk);
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
    static List<Recipient> parseHeader(InputStream envelopeIs, @Nullable ByteArrayOutputStream outHeaderOs)
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

            if (FMKEncryptionMethod.XOR != r.fmkEncryptionMethod()) {
                throw new CDocParseException("Unknown FMK encryption method: " + r.fmkEncryptionMethod());
            }

            if (r.encryptedFmkLength() != Crypto.FMK_LEN_BYTES) {
                throw new CDocParseException("invalid FMK len: " + r.encryptedFmkLength());
            }

            ByteBuffer encryptedFmkBuf = r.encryptedFmkAsByteBuffer();
            byte[] encryptedFmkBytes = Arrays.copyOfRange(encryptedFmkBuf.array(),
                    encryptedFmkBuf.position(), encryptedFmkBuf.limit());
            String keyLabel = r.keyLabel();

            if (r.detailsType() == recipients_ECCPublicKeyDetails) {
                ECCPublicKeyDetails detailsEccPublicKey = (ECCPublicKeyDetails) r.details(new ECCPublicKeyDetails());
                if (detailsEccPublicKey == null) {
                    throw new CDocParseException("error parsing Details");
                }

                try {
                    EllipticCurve curve = EllipticCurve.forValue(detailsEccPublicKey.curve());
                    ECPublicKey recipientPubKey =
                            curve.decodeFromTls(detailsEccPublicKey.recipientPublicKeyAsByteBuffer());
                    ECPublicKey senderPubKey =
                            curve.decodeFromTls(detailsEccPublicKey.senderPublicKeyAsByteBuffer());

                    recipientList.add(new EccPubKeyRecipient(curve, recipientPubKey, senderPubKey,
                            encryptedFmkBytes, keyLabel));
                } catch (IllegalArgumentException illegalArgumentException) {
                    throw new CDocParseException("illegal EC pub key encoding", illegalArgumentException);
                }
            } else if (r.detailsType() == recipients_RSAPublicKeyDetails) {

                RSAPublicKeyDetails rsaPublicKeyDetails = (RSAPublicKeyDetails) r.details(new RSAPublicKeyDetails());
                if (rsaPublicKeyDetails == null) {
                    throw new CDocParseException("error parsing RSAPublicKeyDetails");
                }

                ByteBuffer rsaPubKeyBuf = rsaPublicKeyDetails.recipientPublicKeyAsByteBuffer();
                if (rsaPubKeyBuf == null) {
                    throw new CDocParseException("error parsing RSAPublicKeyDetails.recipientPublicKey");
                }

                ByteBuffer encKekBuf = rsaPublicKeyDetails.encryptedKekAsByteBuffer();
                if (encKekBuf == null) {
                    throw new CDocParseException("error parsing RSAPublicKeyDetails.encryptedKek");
                }

                byte[] rsaPubKeyBytes =
                        Arrays.copyOfRange(rsaPubKeyBuf.array(), rsaPubKeyBuf.position(), rsaPubKeyBuf.limit());
                RSAPublicKey recipientRsaPublicKey;

                try {
                    recipientRsaPublicKey = RsaUtils.decodeRsaPubKey(rsaPubKeyBytes);
                } catch (GeneralSecurityException | IOException ex) {
                    throw new CDocParseException("error decoding RSAPublicKey", ex);
                }

                byte[] encKek = Arrays.copyOfRange(encKekBuf.array(), encKekBuf.position(), encKekBuf.limit());
                recipientList.add(
                        new RSAPubKeyRecipient(recipientRsaPublicKey, encKek, encryptedFmkBytes, keyLabel));

            } else if (r.detailsType() == recipients_KeyServerDetails) {

                KeyServerDetails keyServerDetails = (KeyServerDetails) r.details(new KeyServerDetails());
                if (keyServerDetails == null) {
                    throw new CDocParseException("error parsing KeyServerDetails");
                }

                if (keyServerDetails.recipientKeyDetailsType() == ServerDetailsUnion.ServerEccDetails) {
                    ServerEccDetails serverEccDetails =
                            (ServerEccDetails) keyServerDetails.recipientKeyDetails(new ServerEccDetails());
                    if (serverEccDetails == null) {
                        throw new CDocParseException("error parsing ServerEccDetails");
                    }

                    ECPublicKey recipientPubKey;
                    EllipticCurve curve = EllipticCurve.forValue(serverEccDetails.curve());
                    try {
                        ByteBuffer recipientPubKeyBuf = serverEccDetails.recipientPublicKeyAsByteBuffer();
                        recipientPubKey = curve.decodeFromTls(recipientPubKeyBuf);
                    } catch (IllegalArgumentException iae) {
                        throw new CDocParseException("illegal EC pub key encoding", iae);
                    }
                    String keyServerId = keyServerDetails.keyserverId();
                    String transactionId = keyServerDetails.transactionId();

                    recipientList.add(new EccServerKeyRecipient(curve, recipientPubKey, keyServerId,
                            transactionId, encryptedFmkBytes, keyLabel));
                } else if (keyServerDetails.recipientKeyDetailsType() == ServerDetailsUnion.ServerRsaDetails) {

                    ServerRsaDetails serverRsaDetails =
                            (ServerRsaDetails) keyServerDetails.recipientKeyDetails(new ServerRsaDetails());
                    if (serverRsaDetails == null) {
                        throw new CDocParseException("error parsing ServerRsaDetails");
                    }

                    RSAPublicKey recipientPubKey;
                    try {
                        recipientPubKey = RsaUtils.decodeRsaPubKey(serverRsaDetails.recipientPublicKeyAsByteBuffer());
                    } catch (IOException e) {
                        throw new CDocParseException("error parsing ServerRsaDetails");
                    }

                    String keyServerId = keyServerDetails.keyserverId();
                    String transactionId = keyServerDetails.transactionId();

                    recipientList.add(new RSAServerKeyRecipient(recipientPubKey, keyServerId, transactionId,
                            encryptedFmkBytes, keyLabel));
                } else {
                    log.warn("Unknown KeyServerDetails.recipient_key_details type (ServerDetailsUnion) {}",
                            keyServerDetails.recipientKeyDetailsType());
                }
            } else {
                log.warn("Unknown Details type {}. Ignoring.", r.detailsType());
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
     * Fill RSAPubKeyRecipient with data, so that it is ready to be serialized into CDOC header.
     * @param fmk file master key (plain)
     * @param recipientPubRsaKey  recipients public RSA key
     * @param keyLabel recipientPubRsaKey description
     * @throws GeneralSecurityException if kek encryption with recipientPubRsaKey fails
     */
    static RSAPubKeyRecipient buildRsaRecipient(byte[] fmk, RSAPublicKey recipientPubRsaKey, String keyLabel)
            throws GeneralSecurityException {

        Objects.requireNonNull(recipientPubRsaKey);
        Objects.requireNonNull(fmk);
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Illegal FMK length " + fmk.length);
        }


        byte[] kek = new byte[Crypto.FMK_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(kek);

        byte[] encryptedKek = RsaUtils.rsaEncrypt(kek, recipientPubRsaKey);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        return new RSAPubKeyRecipient(recipientPubRsaKey, encryptedKek, encryptedFmk, keyLabel);
    }

    /**
     * Generate sender key pair for the recipient. Encrypt fmk with KEK derived from generated sender private key
     * and recipient public key
     * @param fmk file master key (plain)
     * @param recipientPubKey  recipient public keys
     * @return EccRecipient with generated sender and recipient public key and
     *          fmk encrypted with sender private and recipient public key
     * @throws InvalidKeyException if recipient key is not suitable
     * @throws GeneralSecurityException if other crypto related exceptions happen
     */
    static EccPubKeyRecipient buildEccRecipient(byte[] fmk, ECPublicKey recipientPubKey, String keyLabel)
            throws InvalidKeyException, GeneralSecurityException {

        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(fmk);
        if (fmk.length != Crypto.FMK_LEN_BYTES) {
            throw new IllegalArgumentException("Illegal FMK length " + fmk.length);
        }

        EllipticCurve curve;
        try {
            curve = EllipticCurve.forPubKey(recipientPubKey);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException
                | NoSuchProviderException generalSecurityException) {
            throw new InvalidKeyException(generalSecurityException);
        }

        try {
            if (!curve.isValidKey(recipientPubKey)) {
                throw new InvalidKeyException("ECKey not valid");
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException("ECKey not valid");
        }

        KeyPair senderEcKeyPair = curve.generateEcKeyPair();
        byte[] kek = Crypto.deriveKeyEncryptionKey(senderEcKeyPair, recipientPubKey, Crypto.CEK_LEN_BYTES);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        return new EccPubKeyRecipient(
                curve, recipientPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk, keyLabel);
    }

    /**
     * Fill EccServerKeyRecipient POJO, so that they are ready to be serialized into CDOC header. Calls
     * {@link #buildEccRecipient(byte[], ECPublicKey, String)} to generate sender key pair and encrypt FMK.
     * Stores sender public key in key server and gets corresponding transactionId from server.
     * @param fmk file master key (plain)
     * @param recipientPubKey  list of recipients public keys
     * @param serverClient used to store sender public key and get transactionId
     * @return For each recipient create EccServerKeyRecipient with fields filled
     */
    static EccServerKeyRecipient buildEccServerKeyRecipient(byte[] fmk, ECPublicKey recipientPubKey,
            String keyLabel, EcCapsuleClient serverClient) throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(serverClient);
        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException("Invalid FMK len");
        }

        EccPubKeyRecipient eccPubKeyRecipient = buildEccRecipient(fmk, recipientPubKey, keyLabel);

        String transactionId = serverClient.storeSenderKey(
            eccPubKeyRecipient.getRecipientPubKey(), eccPubKeyRecipient.getSenderPubKey()
        );
        String serverId = serverClient.getServerIdentifier();

        return new EccServerKeyRecipient(eccPubKeyRecipient.getEllipticCurve(),
                eccPubKeyRecipient.getRecipientPubKey(), serverId, transactionId,
                eccPubKeyRecipient.getEncryptedFileMasterKey(), keyLabel);
    }

    static RSAServerKeyRecipient buildRsaServerKeyRecipient(byte[] fmk, RSAPublicKey recipientPubKey,
                                                            String keyLabel, RsaCapsuleClient serverClient)
            throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientPubKey);
        Objects.requireNonNull(serverClient);
        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException("Invalid FMK len");
        }

        RSAPubKeyRecipient rsaPubKeyRecipient = buildRsaRecipient(fmk, recipientPubKey, keyLabel);

        String transactionId = serverClient.storeRsaCapsule(
                recipientPubKey, rsaPubKeyRecipient.getEncryptedKek()
        );

        String serverId = serverClient.getServerIdentifier();

        return new RSAServerKeyRecipient(recipientPubKey, serverId, transactionId,
                rsaPubKeyRecipient.getEncryptedFileMasterKey(), keyLabel);
    }



    private static Recipient[] buildRecipients(byte[] fmk, Map<PublicKey, String> recipientKeys,
            KeyCapsuleClient serverClient) throws GeneralSecurityException, ExtApiException {

        Objects.requireNonNull(fmk);
        Objects.requireNonNull(recipientKeys);
        if (fmk.length != Crypto.CEK_LEN_BYTES) {
            throw new IllegalArgumentException("Invalid FMK len");
        }

        List<Recipient> result = new ArrayList<>(recipientKeys.size());
        for (Map.Entry<PublicKey, String> recipientEntry : recipientKeys.entrySet()) {
            PublicKey publicKey  = recipientEntry.getKey();
            String keyLabel = recipientEntry.getValue();

            if (publicKey instanceof RSAPublicKey) {
                if (serverClient != null) {
                    RsaCapsuleClient rsaCapsuleClient = new RsaCapsuleClientImpl(serverClient);
                    result.add(buildRsaServerKeyRecipient(fmk, (RSAPublicKey) publicKey, keyLabel, rsaCapsuleClient));
                } else {
                    result.add(buildRsaRecipient(fmk, (RSAPublicKey) publicKey, keyLabel));
                }

            } else if (publicKey instanceof ECPublicKey) {
                if (serverClient != null) {
                    result.add(buildEccServerKeyRecipient(fmk, (ECPublicKey) publicKey, keyLabel,
                            new EcCapsuleClientImpl(serverClient)));
                } else {
                    result.add(buildEccRecipient(fmk, (ECPublicKey) publicKey, keyLabel));
                }
            }
        }

        return result.toArray(new Recipient[0]);
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

    private static List<ArchiveEntry> decrypt(InputStream cdocInputStream, KeyPair recipientKeyPair,
                                              Path outputDir, List<String> filesToExtract, boolean extract,
                                              KeyCapsuleClientFactory capsulesClientFac)
            throws GeneralSecurityException, IOException, CDocParseException, ExtApiException {

        log.trace("Envelope::decrypt");
        log.debug("total available {}", cdocInputStream.available());

        PublicKey recipientPubKey = recipientKeyPair.getPublic();
        ByteArrayOutputStream fileHeaderOs = new ByteArrayOutputStream();
        List<Recipient> recipients = parseHeader(cdocInputStream, fileHeaderOs);

        for (Recipient recipient : recipients) {
            if (recipientPubKey.equals(recipient.getRecipientId())) {
                log.info("Found matching key for {}", recipient.getRecipientPubKeyLabel());
                byte[] kek;
                if (recipient instanceof EccPubKeyRecipient) {
                    ECPublicKey senderPubKey = ((EccPubKeyRecipient) recipient).getSenderPubKey();
                    kek = Crypto.deriveKeyDecryptionKey(recipientKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
                } else if (recipient instanceof EccServerKeyRecipient) {
                    var eccServerKeyRecipient = (EccServerKeyRecipient) recipient;
                    String transactionId = eccServerKeyRecipient.getTransactionId();
                    if (transactionId == null) {
                        log.error("No transactionId for recipient {}", recipientPubKey);
                        throw new CDocParseException("TransactionId missing in record");
                    }

                    String serverId = eccServerKeyRecipient.getKeyServerId();
                    if (serverId == null) {
                        log.error("No serverId for recipient {}", recipientPubKey);
                        throw new CDocParseException("ServerId missing in record");
                    }

                    if (capsulesClientFac == null || capsulesClientFac.getForId(serverId) == null) {
                        log.error("Configuration not found for server {}", serverId);
                        throw new CDocParseException("Configuration not found for server \"" + serverId + "\"");
                    }

                    try {
                        EcCapsuleClient client = new EcCapsuleClientImpl(capsulesClientFac.getForId(serverId));
                        Optional<ECPublicKey> senderPubKeyOptional = client.getSenderKey(transactionId);
                        ECPublicKey senderPubKey = senderPubKeyOptional.orElseThrow();
                        kek = Crypto.deriveKeyDecryptionKey(recipientKeyPair, senderPubKey, Crypto.CEK_LEN_BYTES);
                    } catch (NoSuchElementException nse) {
                        log.info("Key not found for id {} from {}", transactionId, serverId);
                        throw new ExtApiException("Sender key not found for " + transactionId);
                    } catch (ExtApiException apiException) {
                        log.error("Error querying {} for {} ({})", serverId, transactionId, apiException);
                        throw apiException;
                    }

                } else if (recipient instanceof RSAServerKeyRecipient) {
                    var rsaServerKeyRecipient = (RSAServerKeyRecipient) recipient;


                    String transactionId = rsaServerKeyRecipient.getTransactionId();
                    String serverId = rsaServerKeyRecipient.getKeyServerId();
                    if (transactionId == null) {
                        log.error("No transactionId for recipient {}", recipientPubKey);
                        throw new CDocParseException("TransactionId missing in record");
                    }

                    if (serverId == null) {
                        log.error("No serverId for recipient {}", recipientPubKey);
                        throw new CDocParseException("ServerId missing in record");
                    }

                    if (capsulesClientFac == null || capsulesClientFac.getForId(serverId) == null) {
                        log.error("Configuration not found for server {}", serverId);
                        throw new CDocParseException("Configuration not found for server \"" + serverId + "\"");
                    }

                    RsaCapsuleClient client = new RsaCapsuleClientImpl(capsulesClientFac.getForId(serverId));
                    byte[] encryptedKek = client.getEncryptedKek(transactionId).orElseThrow();

                    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) recipientKeyPair.getPrivate();
                    kek = RsaUtils.rsaDecrypt(encryptedKek, rsaPrivateKey);

                } else if (recipient instanceof RSAPubKeyRecipient) {
                    var rsaPubKeyRecipient = (RSAPubKeyRecipient) recipient;
                    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) recipientKeyPair.getPrivate();
                    kek = RsaUtils.rsaDecrypt(rsaPubKeyRecipient.getEncryptedKek(), rsaPrivateKey);
                } else {
                    throw new CDocParseException("Unknown Details.EccRecipient type " + recipient);
                }

                byte[] fmk = Crypto.xor(kek, recipient.getEncryptedFileMasterKey());

                SecretKey hmacKey = Crypto.deriveHeaderHmacKey(fmk);
                SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);

                byte[] hmac = checkHmac(cdocInputStream, fileHeaderOs.toByteArray(), hmacKey);

                log.debug("payload available {}", cdocInputStream.available());

                byte[] additionalData = getAdditionalData(fileHeaderOs.toByteArray(), hmac);
                try (CipherInputStream cis =
                             ChaChaCipher.initChaChaInputStream(cdocInputStream, cekKey, additionalData)) {

                    return Tar.processTarGz(cis, outputDir, filesToExtract, extract);
                }
            }
        }

        log.info("No matching pub key found");
        throw new CDocParseException("No matching pub key found");
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
                                       KeyCapsuleClientFactory keyServerClientFac)
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

    public static List<String> decrypt(InputStream cdocInputStream, KeyPair recipientEcKeyPair, Path outputDir,
                                       List<String> filesToExtract, KeyCapsuleClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocParseException, ExtApiException {

        return decrypt(cdocInputStream, recipientEcKeyPair, outputDir, filesToExtract, true, keyServerClientFac)
                .stream()
                .map(ArchiveEntry::getName)
                .toList();
    }

    public static List<ArchiveEntry> list(InputStream cdocInputStream, KeyPair recipientEcKeyPair,
                                          KeyCapsuleClientFactory keyServerClientFac)
            throws GeneralSecurityException, IOException, CDocParseException, ExtApiException {
        return decrypt(cdocInputStream, recipientEcKeyPair, null, null, false, keyServerClientFac);
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
            if (recipients[i] instanceof EccServerKeyRecipient) {
                var eccServerRecipient = (EccServerKeyRecipient) recipients[i];
                int recipientPubKeyOffset = builder.createByteVector(eccServerRecipient.getRecipientPubKeyTlsEncoded());

                int serverEccDetailsOffset = ServerEccDetails.createServerEccDetails(builder,
                        eccServerRecipient.getEllipticCurve().getValue(),
                        recipientPubKeyOffset
                );

                int keyServerOffset = builder.createString(eccServerRecipient.getKeyServerId());
                int transactionIdOffset = builder.createString(eccServerRecipient.getTransactionId());

                int detailsOffset = KeyServerDetails.createKeyServerDetails(builder,
                        ServerDetailsUnion.ServerEccDetails,
                        serverEccDetailsOffset,
                        keyServerOffset,
                        transactionIdOffset
                );

                int encFmkOffset =
                        RecipientRecord.createEncryptedFmkVector(builder,
                                eccServerRecipient.getEncryptedFileMasterKey());

                int keyLabelOffset = builder.createString(getKeyLabelValue(eccServerRecipient)); //required field

                int recipientOffset = fillRecipientRecord(builder, recipients_KeyServerDetails,
                        detailsOffset, keyLabelOffset, encFmkOffset, eccServerRecipient.getFmkEncryptionMethod());

                recipientOffsets[i] = recipientOffset;

            } else if (recipients[i] instanceof EccPubKeyRecipient) {
                var eccRecipient = (EccPubKeyRecipient) recipients[i];
                int recipientPubKeyOffset = builder.createByteVector(eccRecipient.getRecipientPubKeyTlsEncoded());
                int senderPubKeyOffset = builder.createByteVector(eccRecipient.getSenderPubKeyTlsEncoded());
                int eccPubKeyOffset = ECCPublicKeyDetails.createECCPublicKeyDetails(builder,
                        eccRecipient.getEllipticCurve().getValue(),
                        recipientPubKeyOffset,
                        senderPubKeyOffset
                );

                int encFmkOffset =
                        RecipientRecord.createEncryptedFmkVector(builder, eccRecipient.getEncryptedFileMasterKey());

                int keyLabelOffset = builder.createString(getKeyLabelValue(eccRecipient)); //required field

                int recipientOffset = fillRecipientRecord(builder, recipients_ECCPublicKeyDetails,
                        eccPubKeyOffset, keyLabelOffset, encFmkOffset, eccRecipient.getFmkEncryptionMethod());

                recipientOffsets[i] = recipientOffset;
            } else if (recipients[i] instanceof RSAServerKeyRecipient) {
                RSAServerKeyRecipient rsaServerRecipient = (RSAServerKeyRecipient) recipients[i];

                byte[] rsaPubKeyDer = RsaUtils.encodeRsaPubKey(rsaServerRecipient.getRecipientPubKey());
                int recipientPubKeyOffset = builder.createByteVector(rsaPubKeyDer);

                int serverRsaDetailsOffset = ServerRsaDetails.createServerRsaDetails(builder, recipientPubKeyOffset);

                int keyServerOffset = builder.createString(rsaServerRecipient.getKeyServerId());
                int transactionIdOffset = builder.createString(rsaServerRecipient.getTransactionId());

                int detailsOffset = KeyServerDetails.createKeyServerDetails(builder,
                        ServerDetailsUnion.ServerRsaDetails,
                        serverRsaDetailsOffset,
                        keyServerOffset,
                        transactionIdOffset
                );

                int encFmkOffset =
                        RecipientRecord.createEncryptedFmkVector(builder,
                                rsaServerRecipient.getEncryptedFileMasterKey());

                int keyLabelOffset = builder.createString(getKeyLabelValue(rsaServerRecipient));

                int recipientOffset = fillRecipientRecord(builder, recipients_KeyServerDetails,
                        detailsOffset, keyLabelOffset, encFmkOffset, rsaServerRecipient.getFmkEncryptionMethod());

                recipientOffsets[i] = recipientOffset;

            } else if (recipients[i] instanceof RSAPubKeyRecipient) {
                RSAPubKeyRecipient rsaRecipient = (RSAPubKeyRecipient) recipients[i];

                int recipientPubKeyOffset = builder.createByteVector(
                        RsaUtils.encodeRsaPubKey(rsaRecipient.getRecipientPubKey()));
                int encKekOffset = builder.createByteVector(rsaRecipient.getEncryptedKek());
                int rsaPublicKeyDetailsOffset = RSAPublicKeyDetails.createRSAPublicKeyDetails(builder,
                        recipientPubKeyOffset, encKekOffset);

                int encFmkOffset =
                        RecipientRecord.createEncryptedFmkVector(builder, rsaRecipient.getEncryptedFileMasterKey());

                int keyLabelOffset = builder.createString(getKeyLabelValue(rsaRecipient));

                int recipientOffset = fillRecipientRecord(builder, recipients_RSAPublicKeyDetails,
                        rsaPublicKeyDetailsOffset, keyLabelOffset, encFmkOffset, rsaRecipient.getFmkEncryptionMethod());

                recipientOffsets[i] = recipientOffset;

            } else {
                log.error("Unknown Recipient {}", recipients[i]);
            }
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

    /**
     * Get value for FBS RecipientRecord.key_label
     * @param recipient recipient to generate key label from
     * @return key label that describes recipient
     */
    private static String getKeyLabelValue(Recipient recipient) {
        // KeyLabel is UI specific field, so its value is not specified in the Spec.
        // Required to be filled or deserialization will fail.
        // DigiDoc4-Client uses this field to hint user what type of eID was used for encryption
        // https://github.com
        // /open-eid/DigiDoc4-Client/blob/f4298ad9d2fbb40cffc488bed6cf1d3116dff450/client/SslCertificate.cpp#L302
        // https://github.com/open-eid/DigiDoc4-Client/blob/master/client/dialogs/AddRecipients.cpp#L474

        if (recipient.getRecipientPubKeyLabel() != null) {
            return recipient.getRecipientPubKeyLabel();
        } else {
            return "n/a"; //can't be empty
        }
    }

    /**
     * Add RecipientRecord to the end of {@link FlatBufferBuilder builder}
     * @param builder builder to be updated
     * @param detailsType from {@link ee.cyber.cdoc20.fbs.header.Details}
     * @param detailsOffset detailsOffset in builder
     * @param keyLabelOffset keyLabelOffset in builder
     * @return recipientRecord offset in builder
     */
    private static int fillRecipientRecord(FlatBufferBuilder builder, byte detailsType, int detailsOffset,
                                           int keyLabelOffset, int encFmkOffset, byte fmkEncryptionMethod) {
        RecipientRecord.startRecipientRecord(builder);
        RecipientRecord.addDetailsType(builder, detailsType);
        RecipientRecord.addDetails(builder, detailsOffset);

        RecipientRecord.addKeyLabel(builder, keyLabelOffset);

        RecipientRecord.addEncryptedFmk(builder, encFmkOffset);
        RecipientRecord.addFmkEncryptionMethod(builder, fmkEncryptionMethod);

        return RecipientRecord.endRecipientRecord(builder);
    }
}
