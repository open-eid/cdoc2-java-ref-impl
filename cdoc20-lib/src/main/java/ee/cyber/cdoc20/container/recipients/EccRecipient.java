package ee.cyber.cdoc20.container.recipients;

import ee.cyber.cdoc20.crypto.ECKeys;

import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * Base class for ECC based recipients {@link EccPubKeyRecipient} and {@link EccServerKeyRecipient}.
 */
public class EccRecipient {

    protected final ECPublicKey recipientPubKey;
    protected final byte[] encryptedFmk;
    protected ECKeys.EllipticCurve ellipticCurve;

    public EccRecipient(ECKeys.EllipticCurve eccCurve, ECPublicKey recipientPubKey, byte[] encryptedFmk) {
        this.ellipticCurve = eccCurve;
        this.recipientPubKey = recipientPubKey;
        this.encryptedFmk = encryptedFmk;
    }

    public ECKeys.EllipticCurve getEllipticCurve() {
        return this.ellipticCurve;
    }

    public ECPublicKey getRecipientPubKey() {
        return recipientPubKey;
    }

    /**
     * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
     */
    public byte[] getRecipientPubKeyTlsEncoded() {
        return ECKeys.encodeEcPubKeyForTls(this.ellipticCurve, this.recipientPubKey);
    }

    public byte[] getEncryptedFileMasterKey() {
        return this.encryptedFmk;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EccRecipient that = (EccRecipient) o;
        return Objects.equals(recipientPubKey, that.recipientPubKey)
                && Arrays.equals(encryptedFmk, that.encryptedFmk)
                && ellipticCurve == that.ellipticCurve;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(recipientPubKey, ellipticCurve);
        result = 31 * result + Arrays.hashCode(encryptedFmk);
        return result;
    }
}
