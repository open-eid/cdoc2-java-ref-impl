package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

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
        public byte[] getRecipientPubKeyTlsEncoded() throws NoSuchAlgorithmException {
            return ECKeys.encodeEcPubKeyForTls(EllipticCurve.forValue(this.ellipticCurve), this.recipientPubKey);
        }

        public ECPublicKey getSenderPubKey() {
            return senderPubKey;
        }

        /**
         * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
         */
        public byte[] getSenderPubKeyTlsEncoded()  throws NoSuchAlgorithmException {
            return ECKeys.encodeEcPubKeyForTls(EllipticCurve.forValue(this.ellipticCurve), this.senderPubKey);
        }

        public byte[] getEncryptedFileMasterKey() {
            return this.encryptedFmk;
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
