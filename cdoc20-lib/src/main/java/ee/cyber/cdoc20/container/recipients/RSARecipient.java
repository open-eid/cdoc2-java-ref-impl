package ee.cyber.cdoc20.container.recipients;

import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * Base class for RSAPubKeyRecipient and RSAServerKeyRecipient
 */
public class RSARecipient extends Recipient implements PublicKeyRecipient {

    protected final RSAPublicKey recipientPubKey;

    protected RSARecipient(RSAPublicKey recipient, byte[] encFmk, String recipientLabel) {
        super(encFmk, recipientLabel);
        this.recipientPubKey = recipient;
    }

    public RSAPublicKey getRecipientPubKey() {
        return recipientPubKey;
    }

    @Override
    public Object getRecipientId() {
        return recipientPubKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        RSARecipient that = (RSARecipient) o;
        return Objects.equals(recipientPubKey, that.recipientPubKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), recipientPubKey);
    }
}
