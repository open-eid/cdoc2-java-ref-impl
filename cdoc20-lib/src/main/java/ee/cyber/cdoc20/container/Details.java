package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.fbs.recipients.EllipticCurve;
//import lombok.EqualsAndHashCode;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Details {

    //@EqualsAndHashCode
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
         * @return List of EccRecipients
         */
        public static List<EccRecipient> buildEccRecipients(byte[] fmk, KeyPair senderEcKeyPair,
                                                            List<ECPublicKey> recipients)
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

        //CHECKSTYLE:OFF - generated code
        @SuppressWarnings("java:S3776")
        @Override
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            } else if (!(o instanceof Details.EccRecipient)) {
                return false;
            } else {
                Details.EccRecipient other = (Details.EccRecipient)o;
                if (!other.canEqual(this)) {
                    return false;
                } else if (this.ellipticCurve != other.ellipticCurve) {
                    return false;
                } else {
                    label41: {
                        Object this$recipientPubKey = this.getRecipientPubKey();
                        Object other$recipientPubKey = other.getRecipientPubKey();
                        if (this$recipientPubKey == null) {
                            if (other$recipientPubKey == null) {
                                break label41;
                            }
                        } else if (this$recipientPubKey.equals(other$recipientPubKey)) {
                            break label41;
                        }

                        return false;
                    }

                    Object this$senderPubKey = this.getSenderPubKey();
                    Object other$senderPubKey = other.getSenderPubKey();
                    if (this$senderPubKey == null) {
                        if (other$senderPubKey != null) {
                            return false;
                        }
                    } else if (!this$senderPubKey.equals(other$senderPubKey)) {
                        return false;
                    }

                    if (!Arrays.equals(this.encryptedFmk, other.encryptedFmk)) {
                        return false;
                    } else {
                        return true;
                    }
                }
            }
        }

        protected boolean canEqual(Object other) {
            return other instanceof Details.EccRecipient;
        }

        @Override
        public int hashCode() {
            int result = 1;
            result = result * 59 + this.ellipticCurve;
            Object $recipientPubKey = this.getRecipientPubKey();
            result = result * 59 + ($recipientPubKey == null ? 43 : $recipientPubKey.hashCode());
            Object $senderPubKey = this.getSenderPubKey();
            result = result * 59 + ($senderPubKey == null ? 43 : $senderPubKey.hashCode());
            result = result * 59 + Arrays.hashCode(this.encryptedFmk);
            return result;
        }
        //CHECKSTYLE:ON - generated code

    }
}
