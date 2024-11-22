package ee.cyber.cdoc2.smartid;

import com.nimbusds.jose.JOSEException;
import ee.cyber.cdoc2.auth.AuthTokenVerifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.VerificationException;
import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.cyber.cdoc2.config.SmartIdClientConfigurationImpl;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.exceptions.AuthSignatureCreationException;
import ee.cyber.cdoc2.util.SIDAuthTokenCreator;
import ee.cyber.cdoc2.util.SIDAuthCertData;
import ee.cyber.cdoc2.util.SIDAuthJWSSigner;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc2.ClientConfigurationUtil.initKeySharesConfiguration;
import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
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

    public static final String SERVER1 = "https://cdoc2-css.ria.ee:443";
    public static final String SERVER2 = "https://cdoc2-css.smit.ee:443/css";

    public static final String SHARE_ID1 = "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3";
    public static final String SHARE_ID2 = "5BAE4603-C33C-4425-B301-125F2ACF9B1E";

    public static final String NONCE01 = Base64.getEncoder().encodeToString(
        "01".getBytes(StandardCharsets.UTF_8));
    public static final String NONCE02 = Base64.getEncoder().encodeToString(
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
        nonce1.setNonce(Base64.getDecoder().decode(NONCE01));

        NonceResponse nonce2 = new NonceResponse();
        nonce2.setNonce(Base64.getDecoder().decode(NONCE02));

        try {
            when(mockKeySharesClient1.createKeyShareNonce(any())).thenReturn(nonce1);
            when(mockKeySharesClient2.createKeyShareNonce(any())).thenReturn(nonce2);
        } catch (ApiException e) {
            throw new RuntimeException("Should never be thrown from here");
        }

        return this.sharesFac;
    }

    SmartIdClient setupSIDClient() {
        final String clTestProperties = CLASSPATH + "smartid/smart_id-test.properties";

        SmartIdClientConfiguration sidConf = new SmartIdClientConfigurationImpl(
            loadProperties(clTestProperties)
        ).smartIdClientConfiguration();

        return new SmartIdClient(sidConf);
    }

    SIDAuthJWSSigner setupSIDSigner(SemanticsIdentifier semID) {
        SmartIdClient sidClient = setupSIDClient();
        return new SIDAuthJWSSigner(sidClient, semID);
    }

    @Test
    @Tag("net") //requires external network to connect to SID demo server
    void testCreateAuthToken() throws AuthSignatureCreationException, VerificationException,
        ParseException, JOSEException {

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

        //pub key for validating signature on sdjwt.org
        //log.debug("pub key: {}", SIDAuthCertData.getRSAPublicKeyPkcs1Pem(issCert));

        Map<String, Object> verifiedClaims = AuthTokenVerifier.getVerifiedClaims(token1, issCert,
            SIDAuthCertData::parseSemanticsIdentifier);

        log.debug("claims {}", verifiedClaims);

        //verify issuer
        assertEquals("etsi/PNOEE-" + DEMO_ID_CODE, verifiedClaims.get("iss"));

        // verified claims fields will change in next version
        assertNotNull(verifiedClaims.get("sharedAccessDataPOJO"));
        assertInstanceOf(ShareAccessData.class, verifiedClaims.get("sharedAccessDataPOJO"));

        ShareAccessData data = (ShareAccessData) verifiedClaims.get("sharedAccessDataPOJO");

        assertEquals(SHARE_ID1, data.getShareId());
        assertEquals(NONCE01, data.getNonce());
        assertEquals(SERVER1, data.getServerBaseUrl());
    }

}
