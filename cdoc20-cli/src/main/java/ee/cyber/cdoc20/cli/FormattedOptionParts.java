package ee.cyber.cdoc20.cli;

import java.util.Arrays;
import java.util.Objects;

/**
 * Holds extracted password or secret and label from CLI options.
 * @param optionBytes bytes of password or secret
 * @param label       label
 */
public record FormattedOptionParts(byte[] optionBytes, String label) {
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        FormattedOptionParts that = (FormattedOptionParts) o;
        return Arrays.equals(this.optionBytes, that.optionBytes)
            && this.label.equals(that.label);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            Arrays.hashCode(this.optionBytes),
            this.label
        );
    }

    @Override
    public String toString() {
        return "FormattedOptionParts{"
            + "optionBytes=" + Arrays.toString(this.optionBytes)
            + ", label=" + this.label
            + '}';
    }

}
