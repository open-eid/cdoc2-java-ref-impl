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


public class AuthClientMock {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String DEFAULT_VERIFICATION_CODE = "1234";

    @SuppressWarnings("checkstyle:LineLength")
    public static final String SESSION_TOKEN_BASE64URL = "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6IlFzZnRRdThWRGNyaW1xaGhnc1AvQkNITGIrQkNkaFFLUU1KUStuSVlYZ2kyd2VjSEhhTlAwckFTTTBuaGdqWWJSQUVTZEx5c3JrYzEzRWJlMEU2dUNnPT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiZ01MeEJjbUNic0lmSnJWQk9ZNW9qZXpTMVdqS0srM1dnRkh3aFVJTTJpU0hwVTF3KytLZk1xdjVyckNkOHdxVDJXTmJKYVMvL0lHalhFN2JxRmZxMUVzR0NvWng3WXF4N0NyQys1OFh0c3F5VENlbnN6bGN1aW10ak1CQ0RYT2JSRCtOMS9iTVowTktBeTZpeXlQcmlNS0ZCdm45YUE2N0FkUnVxRyttUDI2M0VLNXJGZ1F6dU5JZ0FiK0Y3TVNMU1ZweXJFMEpWbUtnUWpDa2d1U1ZNTWRSaitTNlpHQVpIeG9ValFUYWttcmFiazlQT1QvNWZ4N3N4bTV5aFkwelJOTE4rRGxNUG1pdEUraG1DM0dDR3hqZDdNbVI1eFJQNGJLWDB5SmFpSVdVaWY3Q0I3VTJCekplZFl2aE9xOXhDTUg5Y1hrR2MrbnBKWWpZUG9VWnlOeDBHTzZVa0MxaEx0ZmRUSlQ0RktMWFoxOVk2TmNhS2JKTDZZY0JaRDdqUFNvWFNTMG5Va1p0dGlTN3BGVSsvYzZUNXFHRjRpT2NVOElxVFNERlFNNkpPSnRzMEUwb3BWMHlMeGxHZ2JXNjFqNmltU29HcGxGLzdrZFladkxSZkZMYXd2Sk1WWnQ3V0F6TEI0aVk2Rk12VzR3dFc3bWQ5cFBsaVpoZGJmOTJORHJqUS9GYnUwQUVqRm8xemdXTi9hSnJyZTNkVHYxM3JMRHBDOHRxRmlCemJKSWNSMjlYYUtIdVR3K05qcW9qTnB6SkV0RjgvY2I4RXpQREpxbHY0Qjl2aGY2UTVacWZ1VFJ2cTFWam5vcjEyejZydGJXMVJCMU52MjlwRVpUNWpLSUVMKy9XVjhlNXJpcy85S2dvSGhCZGphUXkrSk15d1BtemtnQnhXSkhBUi92T0wyR3ZucGNFMTZGem5ubEh1a0Q4Y21JK3NVTlZ6SXorbXBVVGJSM2NNVnRzQnpJbC9UQndYa0Y2RU5OTVhvZzFOQmo1akZjMGs3bGJnQWk0SVR5OWEySis3c1ZtWHpLWTJsWEtIU2pick9kRVZhRW9qaFhHSy9aWURHcUs1UzNKSEJZR1VVUUt4NmxkL2JRb2Y4a3RQZEZ5S3RWeDRhbnE5TXN5L2NFV2ZreU9PcUd1YlQyblh6UStqb2tZZkROdFdKNHZmS1hVQzRRVjRNNCswd3o4M04zU25QNkZiVlgvUUZUeHZQT1hhbGY1Y0dRK3N1NU9IN3JHWVZ5NzVLbS83TXVNdnlYRWFTQTJlUUZIbWJIeW14Slk3cWprODVxbXFVTjdkcStTb2dwT2hCMHFiS290a1lrRUdJZW5BdmJSR1hCbFoxYXd1ZWdJRUNvUCIsInNlcnZlclJhbmRvbSI6Ik56dHFUcWQxYVQ4VW1wYXdEMi9QbStuSyIsInVzZXJDaGFsbGVuZ2UiOiJ2YkRfTkdQWUJsYXVxUWw2SnNlZkxQUmFQMEw2X1hXMDBiZWtDV2J6bWFzIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyJuM0RTeFlUUTNpZmxPMktqZDZjSHNXWHo4aUxSYnZ2Njc1WkkxRWtpbmhvIl0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3NzcwNTMwMjcsImlhdCI6MTc3Njk2NjYyNywiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.15W7YiGj4zetAhvRV4s3yC_fa4v_-OoZzvljt5D30t1lrDgD6aLozwtWfgBIQ5OaL9w15Gl3_UvHj4gXgZPxCA~WyJKZTVNaG9haVpFOE9EM2JNOVR1Z0dRIiwiYXVkIixbeyIuLi4iOiJUVGdBYkJqNURWS1MtUVNWUVVLZnZNU1NqbEJDeU04QlFNVTJWVmtpR1NRIn0seyIuLi4iOiIyYWkxUllaMUhuVlRiVUZuc0tsbWQ0THZkOXBMdWk1aDd0WDJ3VDhDbWFRIn1dXQ~WyJrMmFDOTVEd3ItY1FhYWxfTHBxV3NBIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mi9zZXNzaW9uX25vbmNlL0dFYnRxTWZqdjF0Z19mOFpFQ09QckEiXQ~WyI5aTFmSVF0WkFZWFVTMzVxeXVfeW9BIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0My9zZXNzaW9uX25vbmNlL2p0X0tEUHFGdEgyWVQtTTk2VHNDeWciXQ~";

    // Session token that contains disclosures for:
    //  cdoc2-rp server: https://localhost:7600/session_nonce/849TbD8MOoke1vEKSjDcfA
    //  cdoc2-share server 1: https://localhost:8443/session_nonce/6hNuKAFEHEZOJ8BhIF1J5Q
    //  cdoc2-share server 2: https://localhost:8442/session_nonce/b0y7hzLVtYJLiU6WwP-m-Q
    @SuppressWarnings("checkstyle:LineLength")
    public static final String SESSION_TOKEN_NONCE_LOCALHOST_BASE64URL = "eyJraWQiOiJMM1JyWTVZVnFuN2ZDRWc2aGZfLWxzR1VuaFBjOWRjS3VUZVR2SkhPOVc4IiwidHlwIjoidm5kLmNkb2MyLnNlc3Npb24tdG9rZW4udjIrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwiX3NkIjpbIlRKTlNaaldBOC15dFZZemExb2U3dHdjNVRWVnVCMlQ4R2xqOGFBRVhNMEUiXSwic3ViIjoiZXRzaS9QTk9FRS02MDAwMTAxNzg2OSIsImV4cCI6MTc4MDU4MDIzNSwiaWF0IjoxNzgwNDkzODM1LCJfc2RfYWxnIjoic2hhLTI1NiJ9.p5TUpKT9TgBMlZQbHuONEp_Tcx_XkxgaZ77ZieNDnvfjUh-ab83xKxPMz9AXy2UgLRm4atFCXbMfO06jkr3Icw~WyJibWFZbXFCeTN5aDkyTUNmTXhXYkRBIiwiYXVkIixbeyIuLi4iOiJJa2lEZmpJX3hibjk4WXhjQVJTcUtjeFhrQmRES0ZJSlJBTUdkaEs4TmxnIn0seyIuLi4iOiJ5bUVpZ3hiaTU2U1NmQWxPRUJONzhvc1NzSG1aTzdCa19WNUdOSFA4U2YwIn0seyIuLi4iOiI5ZWJDcjhJZW9HaGkyM2Q2cXMyREhtcGN5S2xhallIQVE0ckJQVkljM1hjIn1dXQ~WyIxT0t6R09hWktJOEduT3JLUWFTYUd3IiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzYwMC9zZXNzaW9uX25vbmNlLzg0OVRiRDhNT29rZTF2RUtTakRjZkEiXQ~WyJFVXZHdk81VUNLZFNmMDhaV2RIYUR3IiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0My9zZXNzaW9uX25vbmNlLzZoTnVLQUZFSEVaT0o4QmhJRjFKNVEiXQ~WyJFd3JzcERVS2ZwREk4clVYRFlXRG5nIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mi9zZXNzaW9uX25vbmNlL2IweTdoekxWdFlKTGlVNld3UC1tLVEiXQ~";

    @SuppressWarnings("checkstyle:LineLength")
    public static final String SID_SIGNING_CERTIFICATE_BASE64URL = "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";

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
