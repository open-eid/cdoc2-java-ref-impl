package ee.cyber.cdoc20.container.recipients;

import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import java.util.Arrays;
import java.util.Objects;

/**
 * Java POJO that represents flatbuffers {@link ee.cyber.cdoc20.fbs.header.RecipientRecord header.RecipientRecord}
 * details union field(s) will be implemented by subclasses.
 */
public abstract class Recipient {
    // header.RecipientRecord specific fields
    protected final byte[] encryptedFmk;
    protected final String recipientKeyLabel;
    protected final byte fmkEncryptionMethod = FMKEncryptionMethod.XOR;

    protected Recipient(byte[] encFmk, String recipientLabel) {
        this.recipientKeyLabel = recipientLabel;
        this.encryptedFmk = encFmk.clone();
    }

    public String getRecipientKeyLabel() {
        return recipientKeyLabel;
    }

    public byte[] getEncryptedFileMasterKey() {
        return this.encryptedFmk;
    }

    public byte getFmkEncryptionMethod() {
        return fmkEncryptionMethod;
    }

    /**
     * Uniquely identifies the recipient. This data is used to find recipients key material from parsed CDOC header
     * * For EC, this is EC pub key.
     * * For RSA, this is RSA pub key
     * @return Object that uniquely identifies Recipient
     */
    public abstract Object getRecipientId();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Recipient recipient = (Recipient) o;
        return fmkEncryptionMethod == recipient.fmkEncryptionMethod
                && Objects.equals(recipientKeyLabel, recipient.recipientKeyLabel)
                && Arrays.equals(encryptedFmk, recipient.encryptedFmk);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(recipientKeyLabel, fmkEncryptionMethod);
        result = 31 * result + Arrays.hashCode(encryptedFmk);
        return result;
    }
}
