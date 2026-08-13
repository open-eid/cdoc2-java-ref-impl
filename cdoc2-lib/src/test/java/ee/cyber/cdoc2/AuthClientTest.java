package ee.cyber.cdoc2;

import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

import ee.cyber.cdoc2.client.AuthClient;
import ee.cyber.cdoc2.client.AuthClientImpl;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static ee.cyber.cdoc2.ClientConfigurationUtil.getAuthClientConfiguration;
import static ee.cyber.cdoc2.config.ConfigurationProperties.*;
import static org.junit.jupiter.api.Assertions.*;


public class AuthClientTest {

    private static final int WIREMOCK_PORT = 7500;
    private static final int SHORT_READ_TIMEOUT_MS = 500;

    private static final String DEFAULT_IDENTIFIER = "etsi/";
    private static final String IDENTIFIER_OK = "PNOEE-40504040001";
    private static final String DEFAULT_MOBILE_NR = "1234567890";
    private static final String DEFAULT_VERIFICATION_CODE = "1234";

    private final AuthClient authClient;
    private AuthClientMock authClientMock;

    AuthClientTest() throws ConfigurationLoadingException, GeneralSecurityException {
        this.authClient = AuthClientImpl.create(ClientConfigurationUtil.getAuthClientConfiguration());
    }

    @RegisterExtension
    static WireMockExtension wiremock = WireMockExtension.newInstance()
        .options(wireMockConfig()
            .httpDisabled(true)
            .httpsPort(WIREMOCK_PORT)
            .keystorePath("wiremock_keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
        )
        .build();

    @BeforeEach
    void setUp() {
        authClientMock = new AuthClientMock(wiremock);
    }

    @Test
    void successfulStartAuth() throws ExtApiException, JsonProcessingException {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubStartAuthResp(authProcessUuid);

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        var startAuthResponse = authClient.startAuth(authIdentity);
        assertEquals(authProcessUuid, startAuthResponse.uuid());
        assertEquals(DEFAULT_VERIFICATION_CODE, startAuthResponse.verificationCode());
    }

    @Test
    void successfulGetAutStatus() throws ExtApiException, JsonProcessingException {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubForAuthStatus(authProcessUuid);

        var authProcessStatusResponse = authClient.pollForCompleteAuthProcessStatus(authProcessUuid);

        assertNotNull(authProcessStatusResponse);
        assertNotNull(authProcessStatusResponse.getStatus());
        assertEquals("COMPLETE", authProcessStatusResponse.getStatus());
    }

    @Test
    void successfulGetWellKnownJwks() throws ExtApiException, JsonProcessingException {
        authClientMock.stubForGetWellKnownJwks();

        var wellKnownResponse = authClient.getWellKnown();

        assertNotNull(wellKnownResponse);
        assertFalse(wellKnownResponse.getKeys().isEmpty());
    }

    @Test
    void networkFaultStartAuth() {
        authClientMock.stubStartAuthWithNetworkFault();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> authClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorStartAuth() {
        authClientMock.stubStartAuthWithServerError();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> authClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().startsWith("Failed to start authentication process"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("AUTH_SERVER_ERROR_CODE"),
            "actual cause message: " + ex.getMessage());
    }

    @Test
    void badRequestStartAuth() {
        authClientMock.stubStartAuthWith400();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> authClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().startsWith("Failed to start authentication process"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundStartAuth() {
        authClientMock.stubStartAuthWith404();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> authClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().startsWith("Failed to start authentication process"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutStartAuth() throws Exception {
        authClientMock.stubStartAuthWithDelay();

        AuthClient clientWithTimeout =
            AuthClientImpl.create(getAuthClientConfiguration(
                Map.of(AUTH_SERVER_CLIENT_READ_TIMEOUT, String.valueOf(SHORT_READ_TIMEOUT_MS))
            ));

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithTimeout.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void badRequestGetAuthStatus() {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubAuthStatusWith400(authProcessUuid);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> authClient.pollForCompleteAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve auth process status"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundGetAuthStatus() {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubAuthStatusWith404(authProcessUuid);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> authClient.pollForCompleteAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve auth process status"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorGetAuthStatus() {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubAuthStatusWithServerError(authProcessUuid);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> authClient.pollForCompleteAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve auth process status"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutGetAuthStatus() throws Exception {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubAuthStatusWithDelay(authProcessUuid);

        AuthClient clientWithTimeout =
            AuthClientImpl.create(getAuthClientConfiguration(
                Map.of(AUTH_SERVER_CLIENT_READ_TIMEOUT, String.valueOf(SHORT_READ_TIMEOUT_MS))
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithTimeout.pollForCompleteAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void pollGetAuthStatusComplete() throws Exception {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubSAuthStatusCompleteOnThirdTry(authProcessUuid);

        AuthClient clientWithPollCount =
            AuthClientImpl.create(getAuthClientConfiguration(
                Map.of(AUTH_SERVER_CLIENT_POLLING_MAX_COUNT, "3",
                    AUTH_SERVER_CLIENT_POLLING_INTERVAL_MS, "100")
            ));

        var authProcessStatusResponse = clientWithPollCount.pollForCompleteAuthProcessStatus(
            authProcessUuid
        );

        assertNotNull(authProcessStatusResponse);
        assertNotNull(authProcessStatusResponse.getStatus());
        assertEquals("COMPLETE", authProcessStatusResponse.getStatus());
    }

    @Test
    void pollGetAuthStatusIncomplete() throws Exception {
        var authProcessUuid = UUID.randomUUID();
        authClientMock.stubSAuthStatusCompleteOnThirdTry(authProcessUuid);

        AuthClient clientWithPollCount =
            AuthClientImpl.create(getAuthClientConfiguration(
                Map.of(AUTH_SERVER_CLIENT_POLLING_MAX_COUNT, "2",
                    AUTH_SERVER_CLIENT_POLLING_INTERVAL_MS, "100")
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithPollCount.pollForCompleteAuthProcessStatus(
                authProcessUuid
            )
        );

        assertTrue(ex.getMessage().contains("Max poll count reached"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void badRequestGetWellKnown() {
        authClientMock.stubWellKnownWith400();

        Exception ex = assertThrows(
            ExtApiException.class,
            authClient::getWellKnown
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve well-known JWKS"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundGetWellKnown() {
        authClientMock.stubWellKnownWith404();

        Exception ex = assertThrows(
            ExtApiException.class,
            authClient::getWellKnown
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve well-known JWKS"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorGetWellKnown() {
        authClientMock.stubWellKnownWithServerError();

        Exception ex = assertThrows(
            ExtApiException.class,
            authClient::getWellKnown
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve well-known JWKS"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutGetWellKnown() throws Exception {
        authClientMock.stubWellKnownWithDelay();

        AuthClient clientWithTimeout =
            AuthClientImpl.create(getAuthClientConfiguration(
                Map.of(AUTH_SERVER_CLIENT_READ_TIMEOUT, String.valueOf(SHORT_READ_TIMEOUT_MS))
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            clientWithTimeout::getWellKnown
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }
}
