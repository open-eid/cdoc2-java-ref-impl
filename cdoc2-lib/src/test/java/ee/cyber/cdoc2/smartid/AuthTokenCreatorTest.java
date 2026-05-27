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

import com.nimbusds.jose.JOSEException;

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
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6ImFaQWZBRW92clVJY1Brcy9XTUZmcG5sWVlVTHhIMGRsQlVDSFhUUnJlazNtQWdsU1JkY01yQ0J6Yk1LeDVBUHNiTWMwU2V1OG9rSmZtZzBvcURORHBRPT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiWmpkaWdCeWo5T256THVDeHljaCsydnhZdjFtcFdJREdqOGtHZHFuNlQySktGLzNUOXhobE1wV0F0MWwrWFZ3cE9aa3d0QnFHMXN3YStWSWg5ZXA3aGtWUFNGaE5ybksya1RqeUlOUlNsM3dPQVRGS0hBSDZQSXpDakExRE16YWxIcG9FWVBnbGk3Mnl0T09sTWFnUldOeXhaNEhtWkJTMDMvaUsrUFFYK1hPTVFINnZiQ09DZUNuL1JZbkV3Tk9jSWRBalZySWUyMVdCVmRuQ0ZkMzlYL3pFSlFSRFQyb3c2UFZkVFB3TEhFdHRRZ2xuQ2NHQ3JhWjJ2S3V6ZnR0K2hDcmhFdkxwdXFvcWJyS3JBUDUzZm1tNEx6eERQR015S09lUzFNdEJTS0VwL294OFhGZnM5dm5uVWJ2Rit0d0tmT0txMTUwTnpjd0JYa09NQzBIbHZrbVlpNUxYR0NQSmV2SDdlQ0hKYkxGMmRxYW12bVNMRVJyemJWQTNvb3lUb05FNWp1a3dJeVU4aU05clZxNFlrSU9SeGxQNGVQYUVWNWtwMllTV1pGYXpSckozT0h1ZFZjaUdDWXdPbS9sUG93dEc5K1o1cUFjdzhzVlJxN09KSVh4ays3cURGVzFYQll6SFFUenZjcm1HbGlGL20zRlhBVUtEamFabWh5OURjSDFyZmphbGFaWnI3WW9yS1haL29tckdlSXg1Wm0xaklLNUJyWlFsR0pEWWRTQWw0bGVDakU1d2hUY2o0R0hGZWtzZWQwU1FwbWRDeG5sWGxUOEtOcVVDY3EzZWd2REVtQUJ5YkVIS0lQMXlaUzBPczdRWms1NGh5QkkxeUNsTDlIc1hReWx2c1F3NTRKMUJHVWRPaTZ2M2xtVHNBbW9tbTVkMVNsbzVQQWhMRHIybFU5d2t5ZkRKbmFhbnRrbDIrbnRpUUZzOEF1WEdqL0l1U3M1MHBSR3NydWZJRk8xSUNiVjh5M3VCdXcxSC9MY2UweTJiTldmcHl1VEhWdWd2c1VVemJ4N0FlcWZCM3p0UzM1VXQwclVrYWdWenh0NE5ZYnczemZjWC9NRTZWVjRwUE01QlRyV0NpcGdNWVZVM0NpRXI4c01na09SYWVRQkNuZ2hvWG15NkhGSThYajBHc28zOEd0SUc1bk9BMmVpUW9mS3N1YU96SjZNaDJodjdORkFPU3VHcmtEVFpXMkNwdUVpZTBNRW1QT3pMeG5pemx6MEVJNGd4dEI5Y25XNnVKZnl1bWV5bWlHVEhrZkZ0UUgyM0lyOGJEcVpPalRCZXFWU1prZkM2cmFueXg2cFZEckNucnFSQklJeWJwYkxPUGlINGVLRG1qYjRLRWNWdyIsInNlcnZlclJhbmRvbSI6IktGdUJkbFA1K3lESytJRm1oTGtQUzJGdyIsInVzZXJDaGFsbGVuZ2UiOiI4a2d5bWp2THZUeHBtbHBpNFRXN21ydlh3TmdkdnA4Z0VENERRcmEtWVdjIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyJuQ0pBOVFkcXFnRFhSNElQenAtMmlodlBtaFBvNC1CUmZZako2WEgwUU40Il0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3NzkwMjg4MjcsImlhdCI6MTc3ODk0MjQyNywiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.LGzmPLtyILUI9n-t7yylwBmjPxe2P6fbq3RKj3VDIvaqYgP-UKbznCEGS0UlpqkNjPN42gjp_JmQYfoPuAcO6g~WyJGQkhxZVNOUXlHLVoxbGVWT3FuSFhRIiwiYXVkIixbeyIuLi4iOiJiT04yYTN3STRJZlowZENvMk9pSFdCQVZkM09jQ3dUd0todjhOTFNOS2JVIn1dXQ~WyJ1c2JDTjdvVnZRZDhPTFgzTG9UUVdRIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzYwMC9zZXNzaW9uX25vbmNlL19FdW9fbzU3Qml2bEU5anRIM0hxeXciXQ~";
    @SuppressWarnings("checkstyle:LineLength")
    private static final String SID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";
    @SuppressWarnings("checkstyle:LineLength")
    private static final String MID_SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL =
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwiX3NkIjpbIndPUFNKSXpFUVJTakpuQ1ljOXpGZE55Ql9Od2ljTlNHMzZDTVp3RmJYeTAiXSwic3ViIjoiZXRzaS9QTk9FRS01MTMwNzE0OTU2MCIsImV4cCI6MTc3OTAyODk0NSwiaWF0IjoxNzc4OTQyNTQ1LCJfc2RfYWxnIjoic2hhLTI1NiJ9.muCkLBhMsiW7dvTuZrdPqQ_wxTtbZoy-iW79sqZ7iGG4omjRE8ZMxZPXM9_ONIF3v9qB7GHoevyfxYNF1uWBBg~WyJVRk1oRXkwUDkyZXlMTFVKRUtwWnJBIiwiYXVkIixbeyIuLi4iOiJxNkdySUl3clp5VndmeFdock9vVDd3RXV2WDlJQ0MzMXl1Q19DN3BlRUtNIn1dXQ~WyJHUl9xS3R6a3FSR0dUQjF5R3Jicl9RIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzYwMC9zZXNzaW9uX25vbmNlLzNTbHZOdmRNRXE1cU1JbjFPRW8wdXciXQ~";
    @SuppressWarnings("checkstyle:LineLength")
    private static final String MID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIDqDCCAy6gAwIBAgIQB9W11BzBABj-0d_AZx6UHzAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjQwNjEyMDY0NTI4WhcNMjkwNjE2MDY0NTI3WjCBlTELMAkGA1UEBhMCRUUxLzAtBgNVBAMMJk1BUlkgw4ROTixPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMSUwIwYDVQQEDBxPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMRIwEAYDVQQqDAlNQVJZIMOETk4xGjAYBgNVBAUTEVBOT0VFLTUxMzA3MTQ5NTYwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWlV1aVSXw6WhagWmFmXE_oe-0R1xZzrHyoiVlgKpGiJ8cwIQLogRGQnWY7NwgQvRHCBmsl99bj57h7SWnd03m6OCAYEwggF9MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1RXzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUweAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNVHQ4EFgQUj8KjnXvGQJCRYOd5LVfPku7QsZwwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMCA2gAMGUCMQCocXWDbBnkM3WEyBdv9Vm0A1MNRv08WrR192dRBcX42Kz5oiH0SdHRJv2ffeuEeSwCMEw2tSA3ClJv233Dl7rIYU_T6UG2NQhvDD5FhnP0umZRmVfAUQ6eVcmU8AhFtNJjwg==";
    @SuppressWarnings("checkstyle:LineLength")
    private static final String MID_SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_FOR_RSA_CERT_BASE64URL =
        "eyJraWQiOiJMM1JyWTVZVnFuN2ZDRWc2aGZfLWxzR1VuaFBjOWRjS3VUZVR2SkhPOVc4IiwidHlwIjoidm5kLmNkb2MyLnNlc3Npb24tdG9rZW4udjIrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwiX3NkIjpbImNvREpsTGJ6OHVaOHRSWVFaTUhYWEdqVGN4eUNyamoxR1JDZmVyTXM5cHciXSwic3ViIjoiZXRzaS9QTk9FRS0zOTkwMTAxOTk5MiIsImV4cCI6MTc3OTg2MTQ5OSwiaWF0IjoxNzc5Nzc1MDk5LCJfc2RfYWxnIjoic2hhLTI1NiJ9.B7iwVcY6yaZDIQBkV-ZNYjXZ2k4lxPQO72FhhBzG9F2fJ3GFcfsct6bHS453Pzw6ir_ufuPC8ZKEN7K3uJbyQQ~WyIwRHJsZV9MOE5seWRFX21FbUNIZDRRIiwiYXVkIixbeyIuLi4iOiI3dk9FVnJxeHQ4Z2JQNmc5MmVmaE5QbkJ4OXBibVJTVlk4SHROdkJPWlVvIn1dXQ~WyIySGY4c1dXbUtBZmNwOHBoUVEzWHl3IiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzYwMC9zZXNzaW9uX25vbmNlL0k5UzF5cmtOeUdJMWxlSnJibHV4d2ciXQ~";
    @SuppressWarnings("checkstyle:LineLength")
    private static final String MID_SIGNING_CERTIFICATE_RSA_BASE64URL =
        "MIIESTCCA9CgAwIBAgIQYoxNTpjf-fpF9YJoFuzfXDAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjUwNTA1MTAzMTAzWhcNMzAwNTA5MTAzMTAyWjBwMQswCQYDVQQGEwJFRTEiMCAGA1UEAwwZVEVTVE5VTUJFUixSU0EsMzk5MDEwOTk5MjETMBEGA1UEBAwKVEVTVE5VTUJFUjEMMAoGA1UEKgwDUlNBMRowGAYDVQQFExFQTk9FRS0zOTkwMTAxOTk5MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMPtigPkrty3_gJXsvsmDkAAYFwiHpRIAKrhqnbwZ6YpF-qsQZQc-8wdZxb6pPVCGGPI4c_nC2Q223Dqt9wOkcL9drwGbLKX3Vlr1pOAaBLYDZ8ci1MW0a91_IAStgS7ieUsUT51xll_J0l79B0MMuV3Op5ZGa3O9XzsVO3OLrY9PkiFWrNjAgydcVKCp3PEoMYRpC0fMNGImRloJa9tltR2yYwIXXKFLP1_OzfJYOcMYcn09fZNjx03HeSiA_W1P3SmRxP8XmpZTPJUxiags2Hwl2KP3VZlOi9_eCBW2-3dvVa3eAmK5tR4Bb0WYzcPE9NEG8uftKcU1LSrqZ4eC_8CAwEAAaOCAX4wggF6MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1RXzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUweAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNVHQ4EFgQU47SEND7ponm7GcYaTxJkydVBQKcwCwYDVR0PBAQDAgeAMAoGCCqGSM49BAMCA2cAMGQCMF8CysKa-wUz8DtLXpaMOozw2_3X2sxC7AgkKbE7iRqZ9RRL9t9K1RBHSwz7YW71YwIwVZWlg2MhdqODcbWTOF4uqS29o9ETkPflLwrqiaCW5qQj2qEffILiNpgY7Adyq366";

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

        testCreateAuthToken(idJwsSigner, loadMIDTestTrustStore(), sessionToken);

        //for validating at sdjwt.org
        logCert(idJwsSigner.getSignerCertificate());
    }

    // requires a running and accessible cdoc2-rp-server with net access (or mobile-id mocks) and
    // the session nonce disclosed by the session token present its database
    @Test
    @Tag("net")
    @Disabled
    void testCreateAuthTokenWithMIDAndRSACertificate() throws Exception {
        String phoneNumber = MIDTestData.OK_RSA_PHONE_NUMBER;
        String identityCode = MIDTestData.OK_RSA_IDENTITY_CODE;

        SessionToken sessionToken = new SessionToken(
            MID_SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_FOR_RSA_CERT_BASE64URL,
            MID_SIGNING_CERTIFICATE_RSA_BASE64URL
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

        testCreateAuthToken(idJwsSigner, loadMIDTestTrustStore(), sessionToken);

        //for validating at sdjwt.org
        logCert(idJwsSigner.getSignerCertificate());
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

        var sidAuthTokenVerificationParams = tokenCreator.getSidRpV3SignatureParameters() != null
            ? new AuthTokenVerifier.SidAuthTokenVerificationParams(
            tokenCreator.getSidRpV3SignatureParameters(),
            "DEMO",
            "smart-id-demo"
        )
            : null;

        TokenVerificationResponse response = authTokenVerifier.verify(
            token1,
            certBase64Url,
            sidAuthTokenVerificationParams,
            tokenCreator.getSidRpV3SignatureParameters() == null
                ? MIDTestData.getDefaultHttpSignatureParams()
                : null
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

    private void logCert(X509Certificate certificate) throws JOSEException {
        String certPubAlgorithm = certificate.getPublicKey().getAlgorithm();
        if ("EC".equals(certPubAlgorithm)) {
            log.debug("EC jwk {}", MIDAuthJWSSignerTest.getECPublicKeyJWK(certificate));
        } else if ("RSA".equals(certPubAlgorithm)) {
            log.debug("RSA jwk {}", MIDAuthJWSSignerTest.getRSAPublicKeyJWK(certificate));
        } else {
            log.debug("Unexpected signer certificate public key algorithm: " + certPubAlgorithm);
        }
    }

}
