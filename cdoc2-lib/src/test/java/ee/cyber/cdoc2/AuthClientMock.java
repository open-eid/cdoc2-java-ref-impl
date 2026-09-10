package ee.cyber.cdoc2;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.eclipse.jetty.http.HttpStatus;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.Scenario;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.cyber.cdoc2.Constants.SESSION_TOKEN_NONCE_LOCALHOST_BASE64URL;
import static ee.cyber.cdoc2.Constants.SID_SIGNING_CERTIFICATE_BASE64URL;


public class AuthClientMock {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String DEFAULT_VERIFICATION_CODE = "1234";

    public static final int TIMEOUT_DELAY_MS = 3_000;

    public static final Map<String, Object> AUTH_STATUS_COMPLETE_RESPONSE = Map.of(
        "status", "COMPLETE",
        "endResult", "OK",
        "sessionToken", SESSION_TOKEN_NONCE_LOCALHOST_BASE64URL,
        "signingCertificate", SID_SIGNING_CERTIFICATE_BASE64URL
    );

    public static final Map<String, Object> AUTH_STATUS_STARTED_RESPONSE = Map.of(
        "status", "STARTED"
    );

    private final WireMockExtension wiremock;

    public AuthClientMock(WireMockExtension wiremock) {
        this.wiremock = wiremock;
    }

    public void stubStartAuthResp(UUID authProccessUuid) throws JsonProcessingException {
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

    public void stubSAuthStatusCompleteOnThirdTry(UUID authProccessUuid) throws JsonProcessingException {
        wiremock.resetScenarios();

        // First response with null request body
        wiremock.stubFor(
            WireMock.get(
                    urlEqualTo("/auth/status/" + authProccessUuid)
                ).inScenario("retry")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse()
                    .withStatus(HttpStatus.OK_200)
                )
                .willSetStateTo("state-2")
        );

        // Second response with STARTED status
        wiremock.stubFor(
            WireMock.get(
                    urlEqualTo("/auth/status/" + authProccessUuid)
                ).inScenario("retry")
                .whenScenarioStateIs("state-2")
                .willReturn(aResponse()
                    .withStatus(HttpStatus.OK_200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(OBJECT_MAPPER.writeValueAsString(AUTH_STATUS_STARTED_RESPONSE))
                )
                .willSetStateTo("state-3")
        );

        // Third response with COMPLETE status
        wiremock.stubFor(
            WireMock.get(
                    urlEqualTo("/auth/status/" + authProccessUuid)
                ).inScenario("retry")
                .whenScenarioStateIs("state-3")
                .willReturn(aResponse()
                    .withStatus(HttpStatus.OK_200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(OBJECT_MAPPER.writeValueAsString(AUTH_STATUS_COMPLETE_RESPONSE))
                )
        );
    }

    public void stubStartAuthWithNetworkFault() {
        wiremock.stubFor(
            WireMock.post(
                urlEqualTo("/auth/start")
            ).willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER))
        );
    }

    public void stubStartAuthWithServerError() {
        wiremock.stubFor(
            WireMock.post(
                urlEqualTo("/auth/start")
            ).willReturn(serverError().withBody(
                """
                    {"errorCode":"AUTH_SERVER_ERROR_CODE"}
                    """
            ))
        );
    }

    public void stubStartAuthWith400() {
        wiremock.stubFor(
            WireMock.post(urlEqualTo("/auth/start"))
                .willReturn(aResponse()
                    .withStatus(HttpStatus.BAD_REQUEST_400)
                    .withHeader("Content-Type", "application/json")
                    .withBody("""
                        {"errorCode":"INVALID_REQUEST"}
                        """))
        );
    }

    public void stubStartAuthWith404() {
        wiremock.stubFor(
            WireMock.post(urlEqualTo("/auth/start"))
                .willReturn(aResponse()
                    .withStatus(HttpStatus.NOT_FOUND_404)
                    .withHeader("Content-Type", "application/json")
                    .withBody("""
                        {"errorCode":"NOT_FOUND"}
                        """))
        );
    }

    public void stubStartAuthWithDelay() {
        wiremock.stubFor(
            WireMock.post(urlEqualTo("/auth/start"))
                .willReturn(aResponse()
                    .withFixedDelay(TIMEOUT_DELAY_MS))
        );
    }

    public void stubAuthStatusWith400(UUID authProcessUuid) {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/auth/status/" + authProcessUuid))
                .willReturn(aResponse()
                    .withStatus(HttpStatus.BAD_REQUEST_400)
                    .withHeader("Content-Type", "application/json")
                    .withBody("""
                        {"errorCode":"INVALID_REQUEST"}
                        """))
        );
    }

    public void stubAuthStatusWith404(UUID authProcessUuid) {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/auth/status/" + authProcessUuid))
                .willReturn(aResponse()
                    .withStatus(HttpStatus.NOT_FOUND_404)
                    .withHeader("Content-Type", "application/json")
                    .withBody("""
                        {"errorCode":"NOT_FOUND"}
                        """))
        );
    }

    public void stubAuthStatusWithServerError(UUID authProcessUuid) {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/auth/status/" + authProcessUuid))
                .willReturn(serverError().withBody("""
                    {"errorCode":"AUTH_SERVER_ERROR_CODE"}
                    """))
        );
    }

    public void stubAuthStatusWithDelay(UUID authProcessUuid) {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/auth/status/" + authProcessUuid))
                .willReturn(aResponse()
                    .withFixedDelay(TIMEOUT_DELAY_MS))
        );
    }

    public void stubWellKnownWith400() {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/.well-known/jwks.jws"))
                .willReturn(aResponse()
                    .withStatus(HttpStatus.BAD_REQUEST_400)
                    .withHeader("Content-Type", "application/json")
                    .withBody("""
                        {"errorCode":"INVALID_REQUEST"}
                        """))
        );
    }

    public void stubWellKnownWith404() {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/.well-known/jwks.jws"))
                .willReturn(aResponse()
                    .withStatus(HttpStatus.NOT_FOUND_404)
                    .withHeader("Content-Type", "application/json")
                    .withBody("""
                        {"errorCode":"NOT_FOUND"}
                        """))
        );
    }

    public void stubWellKnownWithServerError() {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/.well-known/jwks.jws"))
                .willReturn(serverError().withBody("""
                    {"errorCode":"AUTH_SERVER_ERROR_CODE"}
                    """))
        );
    }

    public void stubWellKnownWithDelay() {
        wiremock.stubFor(
            WireMock.get(urlEqualTo("/.well-known/jwks.jws"))
                .willReturn(aResponse()
                    .withFixedDelay(TIMEOUT_DELAY_MS))
        );
    }

    public void stubForAuthStatus(UUID authProccessUuid) throws JsonProcessingException {
        wiremock.stubFor(
            WireMock.get(
                urlEqualTo("/auth/status/" + authProccessUuid)
            ).willReturn(aResponse()
                .withStatus(HttpStatus.OK_200)
                .withHeader("Content-Type", "application/json")
                .withBody(OBJECT_MAPPER.writeValueAsString(AUTH_STATUS_COMPLETE_RESPONSE))
            )
        );
    }

    public void stubForGetWellKnownJwks() throws JsonProcessingException {
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
