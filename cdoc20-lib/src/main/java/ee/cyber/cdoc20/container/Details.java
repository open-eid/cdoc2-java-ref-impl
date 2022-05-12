package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Details {

    private Details() {
    }

    /**
     * ECC recipient using ECCPublicKey. POJO of
     * {@link ee.cyber.cdoc20.fbs.recipients.ECCPublicKey recipients.ECCPublicKey} in CDOC header.
     */
    public static class EccRecipient {

        byte ellipticCurve;
        private final ECPublicKey recipientPubKey;
        private final ECPublicKey senderPubKey;
        private final byte[] encryptedFmk;

        public EccRecipient(EllipticCurve eccCurve, ECPublicKey recipientPubKey, ECPublicKey senderPubKey,
                            byte[] encryptedFmk) {
            this.recipientPubKey = recipientPubKey;
            this.senderPubKey = senderPubKey;
            this.ellipticCurve = eccCurve.getValue();
            this.encryptedFmk = encryptedFmk;
        }


        public ECPublicKey getRecipientPubKey() {
            return recipientPubKey;
        }

        /**
         * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
         */
        public byte[] getRecipientPubKeyTlsEncoded() {
            return ECKeys.encodeEcPubKeyForTls(EllipticCurve.forValue(this.ellipticCurve), this.recipientPubKey);
        }

        public ECPublicKey getSenderPubKey() {
            return senderPubKey;
        }

        /**
         * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
         */
        public byte[] getSenderPubKeyTlsEncoded() {
            return ECKeys.encodeEcPubKeyForTls(EllipticCurve.forValue(this.ellipticCurve), this.senderPubKey);
        }

        public byte[] getEncryptedFileMasterKey() {
            return this.encryptedFmk;
        }

        /**
         * Create EccRecipient list, that contains fmk encrypted with recipient pub key and sender priv key
         *
         * @param fmk             file master key
         * @param senderEcKeyPair EC key pair used to encrypt fmk
         * @param recipients      list of recipients public keys
         * @return List of EccRecipients
         */
        public static List<EccRecipient> buildEccRecipients(EllipticCurve curve, byte[] fmk, KeyPair senderEcKeyPair,
                                                            List<ECPublicKey> recipients)
                throws GeneralSecurityException {

            if (fmk.length != Crypto.CEK_LEN_BYTES) {
                throw new IllegalArgumentException("Invalid FMK len");
            }

            List<EccRecipient> result = new ArrayList<>(recipients.size());

            for (ECPublicKey otherPubKey : recipients) {
                EccRecipient eccRecipient = buildEccRecipient(curve, senderEcKeyPair, otherPubKey, fmk);
                result.add(eccRecipient);
            }
            return result;
        }

        /**
         *
         * @param curve EC curve that sender and recipient must use
         * @param senderEcKeyPair
         * @param recipientPubKey
         * @param fmk plain file master key (not encrypted)
         * @return EccRecipient with sender and recipient public key and fmk encrypted with sender private
         *         and recipient public key
         * @throws GeneralSecurityException
         */
        public static EccRecipient buildEccRecipient(EllipticCurve curve, KeyPair senderEcKeyPair,
                                                     ECPublicKey recipientPubKey, byte[] fmk)
                throws GeneralSecurityException {

            byte[] kek = Crypto.deriveKeyEncryptionKey(senderEcKeyPair, recipientPubKey, Crypto.CEK_LEN_BYTES);
            byte[] encryptedFmk = Crypto.xor(fmk, kek);
            return new EccRecipient(curve, recipientPubKey, (ECPublicKey) senderEcKeyPair.getPublic(), encryptedFmk);
        }


        /**
         * Generate sender key pair for each recipient. Encrypt fmk with KEK derived from generated sender private key
         * and recipient public key
         * @param fmk file master key (plain)
         * @param recipients  list of recipients public keys
         * @return
         * @throws GeneralSecurityException
         */
        public static List<EccRecipient> buildEccRecipients(byte[] fmk, List<ECPublicKey> recipients)
                throws GeneralSecurityException {

            if (fmk.length != Crypto.CEK_LEN_BYTES) {
                throw new IllegalArgumentException("Invalid FMK len");
            }

            List<EccRecipient> result = new ArrayList<>(recipients.size());
            for (ECPublicKey recipientPubKey : recipients) {
                String oid = ECKeys.getCurveOid(recipientPubKey);
                EllipticCurve curve = EllipticCurve.forOid(oid);
                KeyPair senderEcKeyPair = curve.generateEcKeyPair();
                EccRecipient eccRecipient = buildEccRecipient(curve, senderEcKeyPair, recipientPubKey, fmk);
                result.add(eccRecipient);
            }

            return result;
        }

        //CHECKSTYLE:OFF - generated code
        @SuppressWarnings({"java:S3776", "java:S1119", "java:S6201", "java:S117", "java:S1126"})
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
        @SuppressWarnings("java:S117")
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
