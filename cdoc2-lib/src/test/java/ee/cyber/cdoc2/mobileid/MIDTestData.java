package ee.cyber.cdoc2.mobileid;

import ee.cyber.cdoc2.ClientConfigurationUtil;
import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.config.MobileIdClientConfiguration;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

public final class MIDTestData {

    // OK for "TEST of SK ID Solutions EID-Q 2021E" certificate
    public static final String OK_1_IDENTITY_CODE = "51307149560";
    public static final String OK_1_PHONE_NUMBER = "+37269930366";

    public static final String OK_1_CERT_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIDqDCCAy6gAwIBAgIQB9W11BzBABj+0d/AZx6UHzAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEb
        MBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UE
        AwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjQwNjEyMDY0NTI4WhcNMjkw
        NjE2MDY0NTI3WjCBlTELMAkGA1UEBhMCRUUxLzAtBgNVBAMMJk1BUlkgw4ROTixPJ0NPTk5Fxb0txaBV
        U0xJSyBURVNUTlVNQkVSMSUwIwYDVQQEDBxPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMRIwEAYD
        VQQqDAlNQVJZIMOETk4xGjAYBgNVBAUTEVBOT0VFLTUxMzA3MTQ5NTYwMFkwEwYHKoZIzj0CAQYIKoZI
        zj0DAQcDQgAEWlV1aVSXw6WhagWmFmXE/oe+0R1xZzrHyoiVlgKpGiJ8cwIQLogRGQnWY7NwgQvRHCBm
        sl99bj57h7SWnd03m6OCAYEwggF9MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9
        aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1R
        XzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUw
        eAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3
        LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50
        LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNV
        HQ4EFgQUj8KjnXvGQJCRYOd5LVfPku7QsZwwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA2gAMGUC
        MQCocXWDbBnkM3WEyBdv9Vm0A1MNRv08WrR192dRBcX42Kz5oiH0SdHRJv2ffeuEeSwCMEw2tSA3ClJv
        233Dl7rIYU/T6UG2NQhvDD5FhnP0umZRmVfAUQ6eVcmU8AhFtNJjwg==
        -----END CERTIFICATE-----""";

    // OK for "TEST of EID-SK 2016" certificate
    public static final String OK_2_IDENTITY_CODE = "60001017869";
    public static final String OK_2_PHONE_NUMBER = "+37268000769";

    private MIDTestData() {

    }

    public static MobileIdClient getDemoEnvClient() throws ConfigurationLoadingException {
        MobileIdClientConfiguration demoEnvConfiguration = ClientConfigurationUtil.getMobileIdDemoEnvConfiguration();
        return new MobileIdClient(demoEnvConfiguration);
    }
}
