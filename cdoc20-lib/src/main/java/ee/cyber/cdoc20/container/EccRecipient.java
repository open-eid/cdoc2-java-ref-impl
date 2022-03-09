package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.fbs.recipients.EllipticCurve;

public class EccRecipient {

    byte ellipticCurve;
    /**
     * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
     */
    byte[] recipientPubKey;

    /**
     * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
     */
    byte[] senderPubKey;

    public EccRecipient(byte[] recipientPubKey, byte[] senderPubKey) {
        this(EllipticCurve.secp384r1, recipientPubKey, senderPubKey);
    }

    public EccRecipient(byte eccCurve, byte[] recipientPubKey, byte[] senderPubKey) {
        this.recipientPubKey = recipientPubKey;
        this.senderPubKey = senderPubKey;
        this.ellipticCurve = eccCurve;
    }

//    ByteBuffer serialize(ByteBuffer dst) {
//        return dst;
//    }

}
