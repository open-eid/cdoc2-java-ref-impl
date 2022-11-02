package ee.cyber.cdoc20.container.recipients;

import ee.cyber.cdoc20.crypto.ECKeys;

import java.security.interfaces.ECPublicKey;
import java.util.Objects;

/**
 * Base class for ECC based recipients {@link EccPubKeyRecipient} and {@link EccServerKeyRecipient}.
 */
public class EccRecipient extends Recipient {

    // recipient.ECCPublicKeyDetails fields
    protected ECKeys.EllipticCurve ellipticCurve;
    protected final ECPublicKey recipientPubKey;

    public EccRecipient(ECKeys.EllipticCurve eccCurve, ECPublicKey recipient, String recipientLabel, byte[] encFmk) {
        super(encFmk, recipientLabel);
        this.ellipticCurve = eccCurve;
        this.recipientPubKey = recipient;
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

    /**
     *
     * @return recipient EC public key.
     */
    @Override
    public Object getRecipientId() {
        return getRecipientPubKey();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EccRecipient that = (EccRecipient) o;
        return ellipticCurve == that.ellipticCurve && Objects.equals(recipientPubKey, that.recipientPubKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), ellipticCurve, recipientPubKey);
    }
}
