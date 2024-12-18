package ee.cyber.cdoc2.smartid;

import ee.cyber.cdoc2.auth.AuthTokenVerifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.client.smartid.SmartIdClientWrapper;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.cyber.cdoc2.config.SmartIdClientConfigurationImpl;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.util.SIDAuthTokenCreator;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc2.ClientConfigurationUtil.SMART_ID_PROPERTIES_PATH;
import static ee.cyber.cdoc2.ClientConfigurationUtil.initKeySharesConfiguration;
import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;


@ExtendWith(MockitoExtension.class)
public class AuthTokenCreatorTest {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenCreatorTest.class);

    KeyShareClientFactory sharesFac;

    @Mock
    KeySharesClient mockKeySharesClient1;

    @Mock
    KeySharesClient mockKeySharesClient2;

    public static final String SERVER1 = "https://localhost:8443";
    public static final String SERVER2 = "https://cdoc2-css.smit.ee:443/css";

    public static final String SHARE_ID1 = "ff0102030405060708090a0b0c0e0dff";
    public static final String SHARE_ID2 = "5BAE4603-C33C-4425-B301-125F2ACF9B1E";

    public static final String NONCE01 = Base64.getUrlEncoder().withoutPadding().encodeToString(
        HexFormat.of().parseHex("000102030405060708090a0b0c0e0dff"));
    public static final String NONCE02 = Base64.getUrlEncoder().withoutPadding().encodeToString(
        "02".getBytes(StandardCharsets.UTF_8));

    //demo env 30303039914 that automatically authenticates successfully
    private static final String DEMO_ID_CODE = "30303039914";

    KeyShareClientFactory setupMockSharesClientFac() {
        KeySharesConfiguration configuration = initKeySharesConfiguration();
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
            when(mockKeySharesClient1.createKeyShareNonce(any())).thenReturn(nonce1);
            when(mockKeySharesClient2.createKeyShareNonce(any())).thenReturn(nonce2);
        } catch (ApiException e) {
            throw new RuntimeException("Should never be thrown from here");
        }

        return this.sharesFac;
    }

    SmartIdClient setupSIDClient() {
        final String clTestProperties = CLASSPATH + SMART_ID_PROPERTIES_PATH;

        SmartIdClientConfiguration sidConf = new SmartIdClientConfigurationImpl(
            loadProperties(clTestProperties)
        ).smartIdClientConfiguration();

        return new SmartIdClient(sidConf);
    }

    KeyStore loadSIDTestTrustStore() {
        final String clTestProperties = CLASSPATH + SMART_ID_PROPERTIES_PATH;

        SmartIdClientConfiguration sidConf = new SmartIdClientConfigurationImpl(
            loadProperties(clTestProperties)
        ).smartIdClientConfiguration();

        return SmartIdClientWrapper.readTrustedCertificates(sidConf);
    }

    @Test
    @Tag("net") //requires external network to connect to SID demo server
    void testCreateAuthToken() throws Exception {

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

        SIDAuthTokenCreator tokenCreator = new SIDAuthTokenCreator(
            "PNOEE-" + DEMO_ID_CODE,
            shares,
            setupMockSharesClientFac(),
            setupSIDClient()
            );

        String token1 = tokenCreator.getTokenForShareID(SHARE_ID1);

        log.debug("token1: {}", token1);
        X509Certificate issCert = tokenCreator.getAuthenticatorCert();

        KeyStore sidTestTrustStore = loadSIDTestTrustStore();
        AuthTokenVerifier authTokenVerifier = new AuthTokenVerifier(sidTestTrustStore, false);

        Map<String, Object> verifiedClaims = authTokenVerifier.getVerifiedClaims(token1, issCert);

        log.debug("claims {}", verifiedClaims);

        //verify issuer
        assertEquals("etsi/PNOEE-" + DEMO_ID_CODE, verifiedClaims.get("iss"));

        assertNotNull(verifiedClaims.get("aud"));
        assertInstanceOf(List.class, verifiedClaims.get("aud"));

        // JavaScript list are typeless, list can contain any type
        List<?> audList = (List<?>)verifiedClaims.get("aud");

        assertEquals(1, audList.size());

        assertInstanceOf(String.class, audList.get(0));
        String aud = (String)audList.get(0);

        ShareAccessData data = ShareAccessData.fromURL(new URL(aud));

        assertEquals(SHARE_ID1, data.getShareId());
        assertEquals(NONCE01, data.getNonce());
        assertEquals(SERVER1, data.getServerBaseUrl());
    }

}
