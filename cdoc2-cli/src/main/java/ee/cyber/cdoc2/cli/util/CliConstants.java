package ee.cyber.cdoc2.cli.util;

public final class CliConstants {

    public static final String BASE_64_PREFIX = "base64,";

    public static final String LABEL_LOG_MSG = "Label for symmetric key: {}";

    private static final String SYMMETRIC_KEY_DESCRIPTION = "symmetric key with label. "
        + "Must have format";

    private static final String PW_DESCRIPTION = "password with label. Must have format";

    // --secret format description, used in cdoc <cmd> classes
    public static final String SECRET_DESCRIPTION = SYMMETRIC_KEY_DESCRIPTION
        + " <label>:<secret>. <secret> is a base64 encoded binary. "
        + "It must be prefixed with `" + BASE_64_PREFIX + "`";

    // --password format description, used in cdoc <cmd> classes
    public static final String PASSWORD_DESCRIPTION = PW_DESCRIPTION
        + " <label>:<password>. <password> can be plain text or base64 "
        + "encoded binary. In case of base64, it must be prefixed with `" + BASE_64_PREFIX + "`";

    private CliConstants() { }
}
