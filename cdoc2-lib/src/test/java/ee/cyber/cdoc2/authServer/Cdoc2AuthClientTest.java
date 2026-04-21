package ee.cyber.cdoc2.authServer;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.eclipse.jetty.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

import ee.cyber.cdoc2.client.authServer.Cdoc2AuthClient;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.exceptions.CdocAuthClientException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static ee.cyber.cdoc2.ClientConfigurationUtil.getCdoc2AuthClientConfiguration;
import static org.junit.jupiter.api.Assertions.*;


public class Cdoc2AuthClientTest {

    private static final int WIREMOCK_PORT = 8080;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String DEFAULT_IDENTIFIER = "etsi/";
    private static final String IDENTIFIER_OK = "PNOEE-40504040001-DEM0-Q";
    private static final String DEFAULT_MOBILE_NR = "1234567890";
    private static final String DEFAULT_VERIFICATION_CODE = "1234";

    private final Cdoc2AuthClient cdoc2AuthClient;

    Cdoc2AuthClientTest() throws ConfigurationLoadingException {
        this.cdoc2AuthClient = new Cdoc2AuthClient(getCdoc2AuthClientConfiguration());
    }

    @RegisterExtension
    static WireMockExtension wiremock = WireMockExtension.newInstance()
        .options(wireMockConfig().port(WIREMOCK_PORT))
        .build();


    @Test
    void successfulStartAuth() throws CdocAuthClientException, JsonProcessingException {
        var authProccessUuid = UUID.randomUUID();
        stubStartAuthResp(authProccessUuid);

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        var startAuthResponse = cdoc2AuthClient.startAuth(authIdentity);
        assertEquals(authProccessUuid, startAuthResponse.uuid());
        assertEquals(DEFAULT_VERIFICATION_CODE, startAuthResponse.verificationCode());
    }

    @Test
    void successfulGetAutStatus() throws CdocAuthClientException, JsonProcessingException {
        var authProccessUuid = UUID.randomUUID();
        stubForAuthStatus(authProccessUuid);

        var authProcessStatusResponse = cdoc2AuthClient.getAuthProcessStatus(authProccessUuid);

        assertNotNull(authProcessStatusResponse);
        assertNotNull(authProcessStatusResponse.getStatus());
        assertEquals("STARTED", authProcessStatusResponse.getStatus());
    }

    @Test
    void successfulGetWellKnownJwks() throws CdocAuthClientException, JsonProcessingException {
        stubForGetWellKnownJwks();

        var wellKnownResponse = cdoc2AuthClient.getWellKnown();

        assertNotNull(wellKnownResponse);
        assertFalse(wellKnownResponse.getKeys().isEmpty());
    }

    private void stubStartAuthResp(UUID authProccessUuid) throws JsonProcessingException {
        wiremock.stubFor(
            WireMock.post(
                urlEqualTo("/auth/start")
            ).willReturn(aResponse()
                .withStatus(HttpStatus.CREATED_201)
                .withHeader("Content-Type", "application/json")
                .withHeader("Location", "/auth/status/" + authProccessUuid)
                .withBody(OBJECT_MAPPER.writeValueAsString(
                    Map.of("vc", DEFAULT_VERIFICATION_CODE)
                ))
            )
        );
    }

    private void stubForAuthStatus(UUID authProccessUuid) throws JsonProcessingException {
        Map<String, Object> response = Map.of(
            "status", "STARTED",
            "endResult", "string",
            "sessionToken", "string",
            "signingCertificate", "string",
            "signatureParameters", "string"
        );

        wiremock.stubFor(
            WireMock.get(
                urlEqualTo("/auth/status/" + authProccessUuid)
            ).willReturn(aResponse()
                .withStatus(HttpStatus.OK_200)
                .withHeader("Content-Type", "application/json")
                .withBody(OBJECT_MAPPER.writeValueAsString(response))
            )
        );
    }

    private void stubForGetWellKnownJwks() throws JsonProcessingException {
        Map<String, Object> response = Map.of(
            "keys", List.of(
                Map.of(
                    "kid", "1",
                    "kty", "EC",
                    "use", "enc",
                    "crv", "P-256",
                    "x", "",
                    "y", "",
                    "n", "",
                    "e", "",
                    "alg", "RS256"
                )
            )
        );

        wiremock.stubFor(
            WireMock.get(
                urlEqualTo("/.well-known/jwks.jws")
            ).willReturn(aResponse()
                .withStatus(HttpStatus.OK_200)
                .withHeader("Content-Type", "application/json")
                .withBody(OBJECT_MAPPER.writeValueAsString(response))
            )
        );
    }
}
