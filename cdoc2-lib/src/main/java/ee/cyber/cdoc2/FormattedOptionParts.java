package ee.cyber.cdoc2;

import java.util.Arrays;
import java.util.Objects;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;

/**
 * Holds chars of extracted password or secret, label from CLI options and key origin.
 * @param optionChars chars of password or secret
 * @param label       label
 * @param keyOrigin   encryption key origin
 */
public record FormattedOptionParts(
    char[] optionChars,
    String label,
    EncryptionKeyOrigin keyOrigin
) {
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        FormattedOptionParts that = (FormattedOptionParts) o;
        return Arrays.equals(this.optionChars, that.optionChars)
            && this.label.equals(that.label) && this.keyOrigin.equals(that.keyOrigin);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            Arrays.hashCode(this.optionChars),
            this.label,
            this.keyOrigin
        );
    }

    @Override
    public String toString() {
        return "FormattedOptionParts{"
            + "optionChars=" + Arrays.toString(this.optionChars)
            + ", label=" + this.label
            + ", keyOrigin=" + this.keyOrigin
            + '}';
    }

}
