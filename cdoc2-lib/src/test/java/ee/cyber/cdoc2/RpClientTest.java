package ee.cyber.cdoc2;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.RpClient;
import ee.cyber.cdoc2.client.RpClientImpl;
import ee.cyber.cdoc2.client.model.MidAuthenticateRequest;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static ee.cyber.cdoc2.ClientConfigurationUtil.getRpClientConfiguration;
import static ee.cyber.cdoc2.Constants.*;
import static ee.cyber.cdoc2.config.ConfigurationProperties.*;
import static org.junit.jupiter.api.Assertions.*;


public class RpClientTest {
    private static final int WIREMOCK_PORT = 7600;
    private static final int SHORT_READ_TIMEOUT_MS = 500;

    private final RpClient rpClient;
    private RpClientMock rpClientMock;

    RpClientTest() throws ConfigurationLoadingException {
        this.rpClient = RpClientImpl.create(ClientConfigurationUtil.getRpClientConfiguration());
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
        rpClientMock = new RpClientMock(wiremock);
    }

    @Test
    void successfulSidAuthenticate() throws ExtApiException, JsonProcessingException {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubSidAuthenticate(sessionId);

        UUID createdSession = rpClient.sidAuthenticate(
            SESSION_TOKEN_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL,
            RpRequestUtil.createSidAuthenticateRequest()
        );

        assertEquals(sessionId, createdSession);
    }

    @Test
    void successfulSidSession() throws ExtApiException {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubSidSession(sessionId);

        var sidSessionResponse = rpClient.sidSession(
            SESSION_TOKEN_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL,
            sessionId
        );

        assertNotNull(sidSessionResponse);
        assertEquals("COMPLETE", sidSessionResponse.getState().getValue());
    }

    @Test
    void pollSidSessionComplete() throws Exception {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubSidSessionCompleteOnThirdTry(sessionId);

        RpClient clientWithPollCount =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_POLLING_MAX_COUNT, "0",
                    RP_SERVER_CLIENT_POLLING_INTERVAL_MS, "100")
            ));

        var sidSessionResponse = clientWithPollCount.pollForCompleteSidSession(
            SESSION_TOKEN_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL,
            sessionId
        );

        assertNotNull(sidSessionResponse);
        assertEquals("COMPLETE", sidSessionResponse.getState().getValue());
    }

    @Test
    void pollSidSessionInComplete() {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubSidSessionCompleteOnThirdTry(sessionId);

        RpClient clientWithPollCount =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_POLLING_MAX_COUNT, "2",
                    RP_SERVER_CLIENT_POLLING_INTERVAL_MS, "100")
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithPollCount.pollForCompleteSidSession(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                sessionId
            )
        );

        assertTrue(ex.getMessage().contains("Max poll count reached"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void successfulMidAuthenticate() throws ExtApiException, JsonProcessingException {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubMidAuthenticate(sessionId);

        UUID createdSession = callDefaultMidAuthenticate();

        assertEquals(sessionId, createdSession);
    }

    @Test
    void successfulMidSession() throws ExtApiException {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubMidSession(sessionId);

        var midSessionResponse = rpClient.midSession(
            SESSION_TOKEN_BASE64URL,
            MID_SIGNING_CERTIFICATE_BASE64URL,
            sessionId
        );

        assertNotNull(midSessionResponse);
        assertNotNull(midSessionResponse.getData());

        var responseBody = midSessionResponse.getData();
        var responseHeaders = midSessionResponse.getHeaders();
        assertEquals("COMPLETE", responseBody.getState().getValue());

        assertTrue(responseHeaders.containsKey("x-rp-signed-hash"));
        assertTrue(responseHeaders.containsKey("x-rp-name"));
        assertTrue(responseHeaders.containsKey("Signature-Input"));
        assertTrue(responseHeaders.containsKey("Signature"));
    }

    @Test
    void pollMidSessionComplete() throws Exception {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubMidSessionCompleteOnThirdTry(sessionId);

        RpClient clientWithPollCount =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_POLLING_MAX_COUNT, "0",
                    RP_SERVER_CLIENT_POLLING_INTERVAL_MS, "100")
            ));

        var midSessionResponse = clientWithPollCount.pollForCompleteMidSession(
            SESSION_TOKEN_BASE64URL,
            MID_SIGNING_CERTIFICATE_BASE64URL,
            sessionId
        );

        assertNotNull(midSessionResponse);
        assertEquals("COMPLETE", midSessionResponse.getData().getState().getValue());
    }

    @Test
    void pollMidSessionInComplete() {
        UUID sessionId = UUID.randomUUID();
        rpClientMock.stubMidSessionCompleteOnThirdTry(sessionId);

        RpClient clientWithPollCount =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_POLLING_MAX_COUNT, "2",
                    RP_SERVER_CLIENT_POLLING_INTERVAL_MS, "100")
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithPollCount.pollForCompleteMidSession(
                SESSION_TOKEN_BASE64URL,
                MID_SIGNING_CERTIFICATE_BASE64URL,
                sessionId
            )
        );

        assertTrue(ex.getMessage().contains("Max poll count reached"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void successfulGetWellKnownJwks() throws ExtApiException, JsonProcessingException {
        rpClientMock.stubForGetWellKnownJwks();

        var wellKnownResponse = rpClient.getWellKnown();

        assertNotNull(wellKnownResponse);
        assertFalse(wellKnownResponse.getKeys().isEmpty());
    }

    @Test
    void networkFaultSidAuthenticate() {
        rpClientMock.stubSidAuthenticateWithNetworkFault();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidAuthenticate(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                RpRequestUtil.createSidAuthenticateRequest()
            )
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorSidAuthenticate() {
        rpClientMock.stubSidAuthenticateWithServerError();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidAuthenticate(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                RpRequestUtil.createSidAuthenticateRequest()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP SID authenticate request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("RP_SERVER_ERROR_CODE"),
            "actual cause message: " + ex.getMessage());
    }

    @Test
    void badRequestSidAuthenticate() {
        rpClientMock.stubSidAuthenticateWith400();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidAuthenticate(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                RpRequestUtil.createSidAuthenticateRequest()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP SID authenticate request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundSidAuthenticate() {
        rpClientMock.stubSidAuthenticateWith404();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidAuthenticate(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                RpRequestUtil.createSidAuthenticateRequest()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP SID authenticate request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutSidAuthenticate() {
        rpClientMock.stubSidAuthenticateWithDelay();

        RpClient clientWithTimeout =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_READ_TIMEOUT, String.valueOf(SHORT_READ_TIMEOUT_MS))
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithTimeout.sidAuthenticate(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                RpRequestUtil.createSidAuthenticateRequest()
            )
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void networkFaultSidSession() {
        rpClientMock.stubSidSessionWithNetworkFault();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidSession(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorSidSession() {
        rpClientMock.stubSidSessionWithServerError();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidSession(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP SID session request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("RP_SERVER_ERROR_CODE"),
            "actual cause message: " + ex.getMessage());
    }

    @Test
    void badRequestSidSession() {
        rpClientMock.stubSidSessionWith400();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidSession(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP SID session request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundSidSession() {
        rpClientMock.stubSidSessionWith404();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.sidSession(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP SID session request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutSidSession() {
        rpClientMock.stubSidSessionWithDelay();

        RpClient clientWithTimeout =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_READ_TIMEOUT, String.valueOf(SHORT_READ_TIMEOUT_MS))
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithTimeout.sidSession(
                SESSION_TOKEN_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void networkFaultMidAuthenticate() {
        rpClientMock.stubMidAuthenticateWithNetworkFault();

        Exception ex = assertThrows(
            ExtApiException.class,
            this::callDefaultMidAuthenticate
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorMidAuthenticate() {
        rpClientMock.stubMidAuthenticateWithServerError();

        Exception ex = assertThrows(
            ExtApiException.class,
            this::callDefaultMidAuthenticate
        );

        assertTrue(ex.getMessage().startsWith("RP MID authenticate request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("RP_SERVER_ERROR_CODE"),
            "actual cause message: " + ex.getMessage());
    }

    @Test
    void badRequestMidAuthenticate() {
        rpClientMock.stubMidAuthenticateWith400();

        Exception ex = assertThrows(
            ExtApiException.class,
            this::callDefaultMidAuthenticate
        );

        assertTrue(ex.getMessage().startsWith("RP MID authenticate request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundMidAuthenticate() {
        rpClientMock.stubMidAuthenticateWith404();

        Exception ex = assertThrows(
            ExtApiException.class,
            this::callDefaultMidAuthenticate
        );

        assertTrue(ex.getMessage().startsWith("RP MID authenticate request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutMidAuthenticate() {
        rpClientMock.stubMidAuthenticateWithDelay();

        RpClient clientWithTimeout =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_READ_TIMEOUT, String.valueOf(SHORT_READ_TIMEOUT_MS))
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> callDefaultMidAuthenticate(clientWithTimeout)
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void networkFaultMidSession() {
        rpClientMock.stubMidSessionWithNetworkFault();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.midSession(
                SESSION_TOKEN_BASE64URL,
                MID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorMidSession() {
        rpClientMock.stubMidSessionWithServerError();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.midSession(
                SESSION_TOKEN_BASE64URL,
                MID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP MID session request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("RP_SERVER_ERROR_CODE"),
            "actual cause message: " + ex.getMessage());
    }

    @Test
    void badRequestMidSession() {
        rpClientMock.stubMidSessionWith400();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.midSession(
                SESSION_TOKEN_BASE64URL,
                MID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP MID session request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundMidSession() {
        rpClientMock.stubMidSessionWith404();

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> rpClient.midSession(
                SESSION_TOKEN_BASE64URL,
                MID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().startsWith("RP MID session request error"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutMidSession() {
        rpClientMock.stubMidSessionWithDelay();

        RpClient clientWithTimeout =
            RpClientImpl.create(getRpClientConfiguration(
                Map.of(RP_SERVER_CLIENT_READ_TIMEOUT, String.valueOf(SHORT_READ_TIMEOUT_MS))
            ));

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithTimeout.midSession(
                SESSION_TOKEN_BASE64URL,
                MID_SIGNING_CERTIFICATE_BASE64URL,
                UUID.randomUUID()
            )
        );

        assertTrue(ex.getMessage().contains("Failed to connect to server"),
            "actual message: " + ex.getMessage());
    }

    private UUID callDefaultMidAuthenticate() throws ExtApiException {
        return callDefaultMidAuthenticate(rpClient);
    }

    private UUID callDefaultMidAuthenticate(RpClient client) throws ExtApiException {
        MidAuthenticateRequest request = RpRequestUtil.createMidAuthenticateRequest();
        return client.midAuthenticate(
            SESSION_TOKEN_BASE64URL,
            MID_SIGNING_CERTIFICATE_BASE64URL,
            request.getNationalIdentityNumber(),
            request.getPhoneNumber(),
            request.getHash(),
            request.getHashType().getValue(),
            InteractionParams.displayTextAndPin(
                InteractionParams.InteractionLanguage.EN, "displayText")
        );
    }
}
