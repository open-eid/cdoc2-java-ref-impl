package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.fbs.recipients.EllipticCurve;

import java.security.interfaces.ECPublicKey;

public class EccRecipient {

    byte ellipticCurve;

    //byte[] recipientPubKey;
    private ECPublicKey recipientPubKey;

    //byte[] senderPubKey;
    private ECPublicKey senderPubKey;

    //FMK encrypted with KEK
    private byte[] encryptedFmk;

    public EccRecipient(ECPublicKey recipientPubKey, ECPublicKey senderPubKey, byte[] encryptedFmk) {
        this(EllipticCurve.secp384r1, recipientPubKey, senderPubKey, encryptedFmk);
    }

    public EccRecipient(byte eccCurve, ECPublicKey recipientPubKey, ECPublicKey senderPubKey, byte[] encryptedFmk) {
        this.recipientPubKey = recipientPubKey;
        this.senderPubKey = senderPubKey;
        this.ellipticCurve = eccCurve;
        this.encryptedFmk = encryptedFmk;
    }

    public ECPublicKey getRecipientPubKey() {
        return recipientPubKey;
    }

    /**
     * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
     */
    public byte[] getRecipientPubKeyTlsEncoded() {
        return Crypto.encodeEcPubKeyForTls(this.recipientPubKey);
    }

    public ECPublicKey getSenderPubKey() {
        return senderPubKey;
    }

    /**
     * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
     */
    public byte[] getSenderPubKeyTlsEncoded() {
        return Crypto.encodeEcPubKeyForTls(this.senderPubKey);
    }

    public byte[] getEncryptedFileMasterKey() {
        return this.encryptedFmk;
    }

    //    ByteBuffer serialize(ByteBuffer dst) {
//        return dst;
//    }

}
