package ee.cyber.cdoc2.cli.util;

import picocli.CommandLine;

/**
 * picocli converter to convert --password param into LabeledPasswordParam.
 */
public class LabeledPasswordParamConverter implements CommandLine.ITypeConverter<LabeledPasswordParam> {
    @Override
    public LabeledPasswordParam convert(String s) {
        if (s.isEmpty()) {
            return new LabeledPasswordParam(null);
        }
        return new LabeledPasswordParam(FormattedLabeledSecretParam.fromPasswordParam(s));
    }
}
