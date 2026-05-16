package ee.cyber.cdoc2.smartid;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.ClientConfigurationUtil;
import ee.cyber.cdoc2.TrustStoreUtil;
import ee.cyber.cdoc2.auth.AuthTokenVerifier;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.TokenVerificationResponse;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.client.rpserver.Cdoc2RpClient;
import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.crypto.jwt.IdentityJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.MIDAuthJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.SIDAuthJWSSigner;
import ee.cyber.cdoc2.crypto.jwt.SessionToken;
import ee.cyber.cdoc2.crypto.jwt.SessionTokenUtil;
import ee.cyber.cdoc2.crypto.jwt.SidMidAuthTokenCreator;
import ee.cyber.cdoc2.exceptions.UnCheckedException;
import ee.cyber.cdoc2.mobileid.MIDAuthJWSSignerTest;
import ee.cyber.cdoc2.mobileid.MIDTestData;
import ee.cyber.cdoc2.services.Cdoc2Services;

import static ee.cyber.cdoc2.ClientConfigurationUtil.DEMO_ENV_PROPERTIES;
import static ee.cyber.cdoc2.ClientConfigurationUtil.initKeySharesTestEnvConfiguration;
import static ee.cyber.cdoc2.crypto.jwt.SIDAuthCertData.getRSAPublicKeyPkcs1Pem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
public class AuthTokenCreatorTest {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenCreatorTest.class);

    @SuppressWarnings("checkstyle:LineLength")
    // aud https://localhost:7600/session_nonce/-m3KE51cRIeMI3LjZfO57Q
    private static final String SID_SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL =
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6IjJ0K3FpN3lFQlBaMVl3dWZEaHlJSkJUN255S3RvMktML0VPME94Wk5QclFJV0tHOSt4cjU0a3dzVTVCc2tuK2NJK3VEZmpTRWhKMVQyVUNLekJ3U09RPT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiUFRZdkFOdlZIa2pYeTYzUnJMQ3NCdHJSbFRHVmpaeFNHSFVRc0trSjV5UlorYTc0OGFDdTRJbWx5TUFyZm1FL3pHVkdyQkxmZEVnUU5wT2JBVDVHY1UwekMvaUo3c0plSWNDSGVMQ2JyWitySm1uai8vMHUrUlphbmpITFlubkUyaTgxamM1UUVCODZSYjdPSVdSczRpMitWWHkrb0pyd2Yyd1FPRGUvZVBTWHB4T0oyL05GelY1RmFhV2RNS0ZnWTdXM1RkazFRQ1BRNU5qVkZPRWhQdGdXaU02clRobmh6RTluZVhWcXRjN2dMV1BkL2toRUQra0JPd1FrQnJCZEFPVjVyTGh4YmtQYzQxNm9rNmcyd3Z6T1RJTmhuQUhoN3pyeGVPVGx2dy9iaUNxTjU4MHlNejNUTU5jZ24xYU5ESkYveHNwcTlkMDdGaDhjMi9VaG9udVcwK0swSVplK2RGZTZuMms1Tzk0eUFaN29NL2ZHV0RsWUJRbE1IdnNsMkNRWG01R080anZablo0K1M2ckZyV1FsaHVLcGYrZFhEdG1xTmlPTm05NzRYemlmeCtsTzQrN0J3YkthRGRFVFNmQXhESW9DcVFZckFXemh1djdxcUdFSkdnZEM5eVN6SU9qQTBubTB5amZGblNiK2pWdzJEWDhqN3FQWnVLd3RGZng2TVpwRkhTa3BPNWMvQU5UamkzNVVqZ0dmaVlCanFocDk3Y0VuOFRJQUxLOTBrQlkvMVBVRzlqbENMVmtocXZQTmRCR2tKUXhVNXVuLzZBeFBIRWVhV2t1K0pYcFVBR3U0RDZNOGVKNkkrdEhyenJudkNxNzJHWEtrUmc4UGYxQk5BckQ4ZVhmQ1dSSTNwSFZPQmVuT1R6SEMzUEVwZnlpV3htZXMzYVl1eEs0Y1l3NnVIT2RsQWVlQzZzSkhaWXA2RDcyVXQ2OVUvZkhIMGUwZjRCMkJPVmxQZGZMc291c0trSUlrRllISy9penUxNW8vR012Q3p4cnhnNVNtclJRNTV6Y0UvMm5ucGpjUHJ5cng1cmZVVW9qOXltUXlpMFpXaHJPdy9rY04zbUI1NE5UUkdhVyt0K1l1VnMzdXFBTDBOeGYrYUFPOEhMTDd0S2kyblpiZk5EaW5TWlpKVUhQcGo5SWVVU1ZTSnV1M0ljZ1U4bXlZeVROTmJXNXVzeEtjdE5UcytXWkxUK1FTL1hOOTZMMnpuQlA2MXhCYVNzWFNqS1BwT0NZZWN6cE1wUk9RL29NY2VCTjZhc3hUM3lHUWZPVitXL2EyWEs4NzlvMTk0RDM2MUVENERuMFYrZkxNcjlnRE9GZ0dxNHFYV3ZvdmNCenpMekRXNzVyUiIsInNlcnZlclJhbmRvbSI6InNzdldUNjgybUxGeW9mOXd1eGhWWlpVQSIsInVzZXJDaGFsbGVuZ2UiOiJOUWdVMHB2QlRMR0Q0dnZFODhqOEtZcUpfRmRra1NhNnFtNGYzNFB2dzlnIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyIwQkxnXzYtZXM0MXJWb0NwazA5bC0yYjlOR0xDVzZnOFc1Ty1uMG05emhBIl0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3Nzc1NDk1NzUsImlhdCI6MTc3NzQ2MzE3NSwiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.D5MRehLcPSHbUUQWKqly30X99sRdFJNhy6m8wk01NwCmy9dDSUeB6IDqa6gdUScpGM79kHJA5GarZ8GzaKZlqw~WyJwTTR4SkpDSlJaRXNmY0RLQzJVeXlnIiwiYXVkIixbeyIuLi4iOiI3MTZ5YkdkeVNhUkphRVpudkZGYV9zajk1eGVfcXVlZjJNeGxWSDllM0VnIn1dXQ~WyJocGlzTEpRSHJ2anVrTTFBQWk1QnlBIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzYwMC9zZXNzaW9uX25vbmNlLy1tM0tFNTFjUkllTUkzTGpaZk81N1EiXQ~";
    @SuppressWarnings("checkstyle:LineLength")
    private static final String SID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";

    @SuppressWarnings("checkstyle:LineLength")
    private static final String MID_SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL =
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwiX3NkIjpbIkNkYnN1T0QzSU9FTGY2YnQ1Q19mWDhleWlBOFNsVUVCZk9lcjhkRmxKN3ciXSwic3ViIjoiZXRzaS9QTk9FRS01MTMwNzE0OTU2MCIsImV4cCI6MTc3ODkyNjY0OCwiaWF0IjoxNzc4ODQwMjQ4LCJfc2RfYWxnIjoic2hhLTI1NiJ9.pglfEy6PYOlvOIPZsra31pH5dtHDvyWpKfb0DjFGMMHQ1E0g6MgO-NEoea8I0ZcO7Oa_8A3cmMAyC4BCrxBfCQ~WyJobGFjdnhISENfUHJTTzVENXlTY2pRIiwiYXVkIixbeyIuLi4iOiJqOXFULWlPNWdnb0VyUUVaRkN1OWI5Rm5hMHpoWmZKUkk1U1pDekE4c08wIn1dXQ~WyJnanlBWUhJOXBnWmY5dmRkSnVmNjZBIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzYwMC9zZXNzaW9uX25vbmNlLzI3VFNmUW55SlJ4MVFDSC1LNkdvd1EiXQ~";

    @SuppressWarnings("checkstyle:LineLength")
    private static final String MID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIDqDCCAy6gAwIBAgIQB9W11BzBABj-0d_AZx6UHzAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjQwNjEyMDY0NTI4WhcNMjkwNjE2MDY0NTI3WjCBlTELMAkGA1UEBhMCRUUxLzAtBgNVBAMMJk1BUlkgw4ROTixPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMSUwIwYDVQQEDBxPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMRIwEAYDVQQqDAlNQVJZIMOETk4xGjAYBgNVBAUTEVBOT0VFLTUxMzA3MTQ5NTYwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWlV1aVSXw6WhagWmFmXE_oe-0R1xZzrHyoiVlgKpGiJ8cwIQLogRGQnWY7NwgQvRHCBmsl99bj57h7SWnd03m6OCAYEwggF9MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1RXzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUweAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNVHQ4EFgQUj8KjnXvGQJCRYOd5LVfPku7QsZwwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMCA2gAMGUCMQCocXWDbBnkM3WEyBdv9Vm0A1MNRv08WrR192dRBcX42Kz5oiH0SdHRJv2ffeuEeSwCMEw2tSA3ClJv233Dl7rIYU_T6UG2NQhvDD5FhnP0umZRmVfAUQ6eVcmU8AhFtNJjwg==";

    public static final String SERVER1 = "https://localhost:8442";
    public static final String SERVER2 = "https://localhost:8443";

    public static final String SHARE_ID1 = "ff0102030405060708090a0b0c0e0dff";
    public static final String SHARE_ID2 = "5BAE4603-C33C-4425-B301-125F2ACF9B1E";

    public static final String NONCE01 = Base64.getUrlEncoder().withoutPadding().encodeToString(
        HexFormat.of().parseHex("000102030405060708090a0b0c0e0dff"));
    public static final String NONCE02 = Base64.getUrlEncoder().withoutPadding().encodeToString(
        "02".getBytes(StandardCharsets.UTF_8));

    //demo env 40504040001 that automatically authenticates successfully
    private static final String SID_DEMO_SEMANTICS_ID_OK = "PNOEE-40504040001";

    KeySharesClientFactory sharesFac;

    @Mock
    KeySharesClient mockKeySharesClient1;

    @Mock
    KeySharesClient mockKeySharesClient2;

    KeySharesClientFactory setupMockSharesClientFac() {
        KeySharesConfiguration configuration = initKeySharesTestEnvConfiguration();
        sharesFac = new KeySharesClientHelper(
            List.of(mockKeySharesClient1, mockKeySharesClient2),
            configuration
        );

        when(mockKeySharesClient1.getServerIdentifier()).thenReturn(SERVER1);
        when(mockKeySharesClient2.getServerIdentifier()).thenReturn(SERVER2);

        NonceResponse nonce1 = new NonceResponse();
        nonce1.setNonce(NONCE01);

        NonceResponse nonce2 = new NonceResponse();
        nonce2.setNonce(NONCE02);

        try {
            when(mockKeySharesClient1.createKeyShareNonce(any(), any(), any())).thenReturn(nonce1);
            when(mockKeySharesClient2.createKeyShareNonce(any(), any(), any())).thenReturn(nonce2);
        } catch (ApiException e) {
            throw new RuntimeException("Should never be thrown from here");
        }

        return this.sharesFac;
    }

    Cdoc2RpClient setupRpClient() {
        try {
            return Cdoc2Services.initFromProperties(DEMO_ENV_PROPERTIES).get(Cdoc2RpClient.class);
        } catch (GeneralSecurityException e) {
            throw new UnCheckedException(e);
        }
    }

    KeyStore loadSIDTestTrustStore() {
        Cdoc2RpClientConfiguration sidConf = ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();
        return TrustStoreUtil.readSidSigningCertificateTrustStore(sidConf);
    }

    KeyStore loadMIDTestTrustStore() {
        Cdoc2RpClientConfiguration sidConf = ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();
        return TrustStoreUtil.readMidSidSigningCertificateTrustStore(sidConf);
    }

    // requires a running and accessible cdoc2-rp-server with net access (or smart-id mocks) and
    // the session nonce disclosed by the session token present its database
    @Test
    @Tag("net")
    @Disabled
    void testCreateAuthTokenWithSID() throws Exception {
        SessionToken sessionToken = new SessionToken(
            SID_SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL
        );

        EtsiIdentifier etsiIdentifier = new EtsiIdentifier("etsi/" + SID_DEMO_SEMANTICS_ID_OK);
        IdentityJWSSigner idJwsSigner = new SIDAuthJWSSigner(
            etsiIdentifier,
            setupRpClient(),
            InteractionParams.displayTextAndVCCForDocument("Doc123"),
            sessionToken
        );

        testCreateAuthToken(idJwsSigner, loadSIDTestTrustStore(), SessionTokenUtil.createSessionToken());

        //for validating at sdjwt.org
        log.debug("RSA PKCS#1 {}", getRSAPublicKeyPkcs1Pem(idJwsSigner.getSignerCertificate()));
    }

    // requires a running and accessible cdoc2-rp-server with net access (or mobile-id mocks) and
    // the session nonce disclosed by the session token present its database
    @Test
    @Tag("net")
    @Disabled
    void testCreateAuthTokenWithMID() throws Exception {
        String phoneNumber = MIDTestData.OK_1_PHONE_NUMBER;
        String identityCode = MIDTestData.OK_1_IDENTITY_CODE;

        SessionToken sessionToken = new SessionToken(
            MID_SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            MID_SIGNING_CERTIFICATE_BASE64URL
        );

        EtsiIdentifier etsiIdentifier = new EtsiIdentifier("etsi/PNOEE-" + identityCode);

        Cdoc2RpClient demoEnvClient = MIDTestData.getDemoEnvClient();

        IdentityJWSSigner idJwsSigner = new MIDAuthJWSSigner(
            etsiIdentifier,
            phoneNumber,
            demoEnvClient,
            null,
            sessionToken
        );

        testCreateAuthToken(idJwsSigner, loadMIDTestTrustStore(), null);

        //for validating at sdjwt.org
        log.debug("EC jwk {}", MIDAuthJWSSignerTest.getECPublicKeyJWK(idJwsSigner.getSignerCertificate()));

    }

    void testCreateAuthToken(
        IdentityJWSSigner idJwsSigner,
        KeyStore trustStore,
        SessionToken sessionToken
    ) throws Exception {

        List<KeyShareUri> shares = List.of(
            new KeyShareUri(
                SERVER1,
                SHARE_ID1
            ),
            new KeyShareUri(
                SERVER2,
                SHARE_ID2
            )
        );

        SidMidAuthTokenCreator tokenCreator = new SidMidAuthTokenCreator(
            idJwsSigner,
            shares,
            setupMockSharesClientFac(),
            sessionToken
        );

        String token1 = tokenCreator.getTokenForShareID(SHARE_ID1);

        log.debug("token1: {}", token1);
        X509Certificate issCert = tokenCreator.getAuthenticatorCert();
        log.debug("signatureParams: {}", tokenCreator.getSidRpV3SignatureParameters());

        AuthTokenVerifier authTokenVerifier = new AuthTokenVerifier(trustStore, false);

        String certBase64Url = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(issCert.getEncoded());

        TokenVerificationResponse response = authTokenVerifier.verify(
            token1,
            certBase64Url,
            tokenCreator.getSidRpV3SignatureParameters(),
            "DEMO",
            "smart-id-demo"
        );

        String expectedSemanticsId = tokenCreator.getSidRpV3SignatureParameters() == null
            ? "PNOEE-" + MIDTestData.OK_1_IDENTITY_CODE
            : SID_DEMO_SEMANTICS_ID_OK;

        assertEquals(expectedSemanticsId, response.identifier().getSemanticsIdentifier());

        ShareAccessData data = ShareAccessData.fromURL(response.nonceUri().toURL());

        assertEquals(SHARE_ID1, data.getShareId());
        assertEquals(NONCE01, data.getNonce());
        assertEquals(SERVER1, data.getServerBaseUrl());
    }

}
