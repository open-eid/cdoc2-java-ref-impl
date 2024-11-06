package ee.cyber.cdoc2.cli.util;

import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;

import javax.annotation.Nullable;


/**
 * Wrap {@link LabeledPassword} to allow nonNull empty values required for "--password" without
 * parameter where label and password are read interactively
 * @param labeledPassword label and password provided as CLI parameter.
 *                        null when --password param was without parameters
 * @see {@link LabeledPasswordParamConverter}
 */
public record LabeledPasswordParam(@Nullable LabeledPassword labeledPassword) {

    /**
     * --password param was provided without arguments.
     * @return true if password provided without arguments, otherwise false
     */
    public boolean isEmpty() {
        return (labeledPassword == null);
    }

}
