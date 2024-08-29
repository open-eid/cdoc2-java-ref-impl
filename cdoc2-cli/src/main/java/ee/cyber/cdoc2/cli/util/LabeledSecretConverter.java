package ee.cyber.cdoc2.cli.util;

import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import picocli.CommandLine;

/**
 * picocli converter to convert --secret parameter into LabeledSecret
 */
public class LabeledSecretConverter implements CommandLine.ITypeConverter<LabeledSecret> {
    @Override
    public LabeledSecret convert(String s) {
        return FormattedLabeledSecretParam.fromSecretParam(s);
    }
}
