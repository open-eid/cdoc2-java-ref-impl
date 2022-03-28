package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.fbs.recipients.EllipticCurve;
import lombok.EqualsAndHashCode;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

public class Details {
    @EqualsAndHashCode
    public static class EccRecipient {

        byte ellipticCurve;

        //byte[] recipientPubKey;
        private final ECPublicKey recipientPubKey;

        //byte[] senderPubKey;
        private final ECPublicKey senderPubKey;

        //FMK encrypted with KEK
        private final byte[] encryptedFmk;

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
            return ECKeys.encodeEcPubKeyForTls(this.recipientPubKey);
        }

        public ECPublicKey getSenderPubKey() {
            return senderPubKey;
        }

        /**
         * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
         */
        public byte[] getSenderPubKeyTlsEncoded() {
            return ECKeys.encodeEcPubKeyForTls(this.senderPubKey);
        }

        public byte[] getEncryptedFileMasterKey() {
            return this.encryptedFmk;
        }

        /**
         * Create EccReipient list, that contains fmk encrypted with recipient pub key and sender priv key
         *
         * @param fmk             file master key
         * @param senderEcKeyPair EC key pair used to encrypt fmk
         * @param recipients      list of recipients public keys
         * @return
         */
        public static List<EccRecipient> buildEccRecipients(byte[] fmk, KeyPair senderEcKeyPair, List<ECPublicKey> recipients)
                throws NoSuchAlgorithmException, InvalidKeyException {

            if (fmk.length != Crypto.CEK_LEN_BYTES) {
                throw new IllegalArgumentException("Invalid FMK len");
            }

            List<EccRecipient> result = new ArrayList<>(recipients.size());

            for (ECPublicKey otherPubKey : recipients) {
                byte[] kek = Crypto.deriveKeyEncryptionKey(senderEcKeyPair, otherPubKey, Crypto.CEK_LEN_BYTES);
                byte[] encryptedFmk = Crypto.xor(fmk, kek);
                EccRecipient eccRecipient =
                        new EccRecipient(otherPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk);
                result.add(eccRecipient);
            }
            return result;
        }

        //    ByteBuffer serialize(ByteBuffer dst) {
//        return dst;
//    }

    }
}
