package ee.cyber.cdoc20.server;

/**
 * Test scenario identifiers
 */
public final class ScenarioIdentifiers {
    private ScenarioIdentifiers() {
    }

    public static final String POS_01 = "ECC-PUT_CAPSULE-POS-01-ONCE";
    public static final String POS_02 = "ECC-GET_CAPSULE-POS-02-CORRECT_REQUEST";

    public static final String NEG_02 = "GET_CAPSULE-NEG-02-NON_EXISTING_TRANSACTION_ID";
    public static final String NEG_03 = "GET_CAPSULE-NEG-03-RANDOM_UUID_TRANSACTION_ID";
    public static final String NEG_04 = "GET_CAPSULE-NEG-04-TOO_SHORT_TRANSACTION_ID";
    public static final String NEG_05 = "GET_CAPSULE-NEG-05-EMPTY_STRING_TRANSACTION_ID";
    public static final String NEG_06 = "GET_CAPSULE-NEG-06-TOO_LONG_RANDOM_STRING_TRANSACTION_ID";
    public static final String NEG_07 = "ECC-GET_CAPSULE-NEG-07-PUBLIC_KEY_NOT_MATCHING";
}
