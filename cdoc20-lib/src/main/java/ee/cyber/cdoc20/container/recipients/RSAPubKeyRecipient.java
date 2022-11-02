package ee.cyber.cdoc20.container.recipients;

import javax.validation.constraints.NotNull;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * RSA-OAEP recipient using RSAPublicKey. POJO of flatbuffers
 * {@link ee.cyber.cdoc20.fbs.recipients.RSAPublicKeyDetails recipients.RSAPublicKeyDetails} in CDOC header.
 */
public class RSAPubKeyRecipient extends Recipient {

    public RSAPubKeyRecipient(@NotNull RSAPublicKey recipient, @NotNull byte[] encryptedKek,
                              @NotNull byte[] encryptedFmk, String recipientLabel) {
        super(encryptedFmk, recipientLabel);
        this.recipientPubKey = recipient;
        this.encryptedKek = encryptedKek;
    }

    public RSAPublicKey getRecipientPubKey() {
        return recipientPubKey;
    }

    public byte[] getEncryptedKek() {
        return encryptedKek;
    }


    /**
     * @return recipient RSA public key
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
        RSAPubKeyRecipient that = (RSAPubKeyRecipient) o;
        return Objects.equals(recipientPubKey, that.recipientPubKey) && Arrays.equals(encryptedKek, that.encryptedKek);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), recipientPubKey);
        result = 31 * result + Arrays.hashCode(encryptedKek);
        return result;
    }

    protected final RSAPublicKey recipientPubKey;
    protected byte[] encryptedKek;

}
