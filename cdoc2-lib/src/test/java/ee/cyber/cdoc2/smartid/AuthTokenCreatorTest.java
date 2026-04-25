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
import ee.cyber.cdoc2.auth.AuthTokenVerifierV2;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.TokenVerificationResponse;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.client.rpserver.Cdoc2RpClient;
import ee.cyber.cdoc2.client.smartid.SidValidationUtil;
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
    private static final String SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL =
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6InpiN1Izb2pNbXR0QnV0U0l0d0tFcEkrWUx3TCt0b3VhMEpWV09IdkNTSm5yMU1ESWZ4c2tuSHRZdlA3MXBCZFg1aFRxUzF1MTB4NUpDK1hZQy9sUEJRPT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiaWJkL2N5L3hmaWtqQS9oY0ZGcURlVG5Ra2lLbjdTWVVSVlhlZ0hsK2FmZCt5bXVvTDlUK3dXSW1jSWIxaEJuNURQKzkxcHYybmdpTEVMNTdQZk1hTFlaazVoY3ZFYm0vVHd4aERuQ2daWDN6RS9iWGc5VlhGbE9rU1BlOUJVRlRWOG5yNHBkU1dxbmt1Umt6b1Y0ZTg1bXhtR0tKMy9RbHJoWGFtZ1JHQUlrVDcrQTQwa0YrWkl2V25SMEh3Y2o0SnlYNlM3YlhtSU11Z2VhTUUwdkFKYnlKdmtOQWFsbU9HQjN5QUZpTExuWFdNZ1ZmMDE4Z2hxTExOUUt5WU5jWXhUOWRPeDM5VUtBNmwzQWdQVXVVSVY1NjE2aVFidUNmazJyWjFJcUMzY2JIbGNwa3NoRHRvS21hRkROSUZMeGl3SmJQcGtyMHdic0kyUktlVXZweklxOXZGVXpoZTRrN0ZFTENWZVcvNmx0NEFvUHJSMklIZU5teldTUGVEOUxHTkRONnZpVDdsRXZ0ZDJJdXpoNWd5TVdNNXI5R0Y1L2NkZUVEZG0vQUJFbFdIeGFTRlhPZWVjZG9rS0Z1bmQvWG1wNXhGdDlGY3hsRmxIY1pwbEhFZHRNTCtHK0JjbnRBYmdoYU14N2FxVnBxbGE3aHpTRDhDdEFDOGNnR0MrZ2NpVjRVM0tyZVgwdFFreHFXemp1bEZTOGp4RmdRU2FGK3J6d0dkWHA4MEd4L29ZZkhYalVKZUNrY3U4dlArSG9QTHBDUXpQbHRQeTljeUV2VTYxNk11UXNEalVFZFB3T3NVb3JzVUxFbTBQNklwSmcvL1VKOE9JRGM5WTVjcUF0TTRuWW1PbXpFUHgrTDBreS9lVzRpUXJydldQZXlraVhRYmNTSDFkNTNjdWdhbHgyWXRUOWdJVWhrYUFRTGdWeGFmU1ZtSVNLYXoyZjBySHByaitJaW52aktGTkNtY1kzSTJmdEtEcU54VE9JR2JxVXRiSUVaUXRzL0FsbXp5eS9KRlFWN0wxODZxN3hXK0gvT3YrYXhIVDM1SWZIajJoNko0K1NjakxGMGxNdXhYT25neFY5Z2ExVnl5NlpkRnhXM0VjODcyOTl4V3JHNkFZZkVMcXNEaStkOFdIcXVNUUZ1T0JyUnlzWURqWlVwbDd3Q2QxU2ZBNkFYSWZ0ZzlCN3RmKzh1alBTelRlSlVjeG1DdWVTNThNQU43SDFzWWpHU295RUI1di9zSFdMM2ZLeHFyVHU3M1Y5KzhPdm9ia3Jmc0FqTDZuaEJkR1JCS0xGak5BOE9OVWVNR1VDK29wSll0QmNQYXNwN0I2aG5icUZBcElWZ1BJWURXa1oyNzkxMCIsInNlcnZlclJhbmRvbSI6IkFnUCtscDNzdG8wc1A1aU1hOWJXcEtQZSIsInVzZXJDaGFsbGVuZ2UiOiJUb2lzN2VlY0hpT3BvakExOGJ5V0dyMzc2em9LaWxDY2hJcmRWZFBjYVlzIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyJqYVdIUXRCVjRzUW1qY1Y0eVF3SmtEb25GQmhncTE1U1BGSVNGWHVjdHdRIl0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3NzcxOTc1MjcsImlhdCI6MTc3NzExMTEyNywiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.f3HHOW4R8veS1ST14aaYAtu9H6GVMeDMDGwhybEyLw1A7lDy5hlj5NxXOvotuPsFfPv3y9LiYUo7TwL3K_v_RA~WyJpRWN4eXg4SmJZVDZRb25VeUhYTGdRIiwiYXVkIixbeyIuLi4iOiJnUU92OGpyRnB0djQxb21WQ2dTVFNfX1h6S1ZXNUZkM2JDWXFMWUhndjE4In0seyIuLi4iOiJyWTU3YmNfVVM4TTVzVFlNLUtUYUQzTnhiZWhoY3RUeEhOV2xvai1aazRvIn1dXQ~WyI5ekpEWTkwQ3U4WHY0MWZxdDhJbWtnIiwiaHR0cDovL2xvY2FsaG9zdDo5MDgwL3Nlc3Npb25fbm9uY2VfMi9uclZjU0VjSHVXdDJTS2Zqa01tNlJRIl0~";
    @SuppressWarnings("checkstyle:LineLength")
    private static final String SID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";

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
        return SidValidationUtil.readTrustStore(sidConf);
    }

    // requires a running and accessible cdoc2-rp-server with net access or smart-id mocks
    @Test
    @Tag("net")
    @Disabled
    void testCreateAuthTokenWithSID() throws Exception {
        SessionToken sessionToken = new SessionToken(
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
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

    @Test
    @Tag("net")
        //requires external network to connect to SID demo server
    void testCreateAuthTokenWithMID() throws Exception {
        String phoneNumber = MIDTestData.OK_1_PHONE_NUMBER;
        String identityCode = MIDTestData.OK_1_IDENTITY_CODE;

        EtsiIdentifier etsiIdentifier = new EtsiIdentifier("etsi/PNOEE-" + identityCode);

        MobileIdClient demoEnvClient = MIDTestData.getDemoEnvClient();

        IdentityJWSSigner idJwsSigner = new MIDAuthJWSSigner(etsiIdentifier, phoneNumber, demoEnvClient, null);

        testCreateAuthToken(idJwsSigner, demoEnvClient.readTrustedCertificates(), null);

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

        AuthTokenVerifierV2 authTokenVerifier = new AuthTokenVerifierV2(trustStore, false);

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
