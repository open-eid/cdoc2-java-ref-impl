package ee.cyber.cdoc20.cli;

import java.util.Arrays;
import java.util.Objects;

/**
 * Holds chars of extracted password or secret and label from CLI options.
 * @param optionChars chars of password or secret
 * @param label       label
 */
public record FormattedOptionParts(char[] optionChars, String label) {
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
            && this.label.equals(that.label);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            Arrays.hashCode(this.optionChars),
            this.label
        );
    }

    @Override
    public String toString() {
        return "FormattedOptionParts{"
            + "optionChars=" + Arrays.toString(this.optionChars)
            + ", label=" + this.label
            + '}';
    }

}
