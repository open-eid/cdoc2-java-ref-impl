package ee.cyber.cdoc2.rpserver;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.eclipse.jetty.http.HttpStatus;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;


import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;


public class Cdoc2RpClientMock {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @SuppressWarnings("checkstyle:LineLength")
    private static final String MID_SESSION_RESPONSE_OK = """
        {
          "state": "COMPLETE",
          "result": "OK",
          "signature": {
            "value": "IO6qDBcUtpIpcQSuTVp49TJ3jbJc+WA0z+26JSFgfW2x29y2I1dSMeHfUewAv4k55YxT1mYKw9DW9Efagp6tWg==",
            "algorithm": "SHA256WithECEncryption"
          },
          "cert": "MIIDqDCCAy6gAwIBAgIQB9W11BzBABj+0d/AZx6UHzAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjQwNjEyMDY0NTI4WhcNMjkwNjE2MDY0NTI3WjCBlTELMAkGA1UEBhMCRUUxLzAtBgNVBAMMJk1BUlkgw4ROTixPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMSUwIwYDVQQEDBxPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMRIwEAYDVQQqDAlNQVJZIMOETk4xGjAYBgNVBAUTEVBOT0VFLTUxMzA3MTQ5NTYwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWlV1aVSXw6WhagWmFmXE/oe+0R1xZzrHyoiVlgKpGiJ8cwIQLogRGQnWY7NwgQvRHCBmsl99bj57h7SWnd03m6OCAYEwggF9MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1RXzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUweAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNVHQ4EFgQUj8KjnXvGQJCRYOd5LVfPku7QsZwwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA2gAMGUCMQCocXWDbBnkM3WEyBdv9Vm0A1MNRv08WrR192dRBcX42Kz5oiH0SdHRJv2ffeuEeSwCMEw2tSA3ClJv233Dl7rIYU/T6UG2NQhvDD5FhnP0umZRmVfAUQ6eVcmU8AhFtNJjwg==",
          "time": "2026-05-12T10:52:20Z",
          "traceId": "d8de38e7bb5d8f8a"
        }
        """;

    @SuppressWarnings("checkstyle:LineLength")
    private static final String SID_SESSION_RESPONSE_OK = """
        {
          "state": "COMPLETE",
          "result": {
            "endResult": "OK"
          },
          "signatureProtocol": "ACSP_V2",
          "signature": {
            "value": "Vak2Q0NiFnh6+lW+YaJuB8yMYM7k3I5QfsUxS3Y1Ddm3qy6HvebLl0/t17dq289/+4mGx45qnHVNj1CzqF88lYFpwAQXFc5XiHtYbvnENgjwLSfrQ9mrSt0phemAK29GzAexilPPy5+PdeCdO+TEuMIhi/qkKhL+lk5d1flmrWZQ4B0H7kXTqRjJvCAUc8bsdM7SLV5jZuEIhOqTCsyDY3FZmyJi4ms8SsOmYCy/Do20CIiQbv75eunKfTKciqVnOA+WYN5OXLJVqhgaHJ+hYiYA+QXOvIIYKVIUdB1rDRnKwwvZk1lZ3oKW1r7XGkovbmwRz+NpmHTyMUubXXQHYah3T4h7vf0C14MBpupWRB47s6rsdPZzH2No7AoDGjMGAMEWg5rdB45fYXbjRV2T69e4c47VpubG1DXTsoXowe/yzXdIjUYfZDwozzW6+IXTdAKL4LP6wmCU+PxP/GfYQ1k1w3fXjh4XeO9QmipRDEle2l0z6nYJaGuIYCb7pDh6ZoJllyKSmhqWG0PMLod34Lo1MMP4WGvLe86/fiTFPbh/VR981MIjz5xIRaSxFZQmNzI5IvzORskgsHGALb7Nb51q3jPKE2D1UOrQN6N6DMbGFMFR/7vRgkvUbeC0jAWevVrssEK77d5OmgXqk7sevYDwP1WnmBwr2ov/Tt+AM58BTgdHsnWRw6hL1mS9+DzCaCuDb/+vspiZnVjP9S9ckmCLP8yrwzL8Myj5lS62Rta727GulSUet21euQl0E2CuDpSoiKuO3NkYWqskfCowb0GiiX0oZe98mFiBFo1Za5Tb207fPOQyGAwY29k0/XaYxwMPsU7/hwI5Ba8iek1A09Et3HB0q0hXeKyWl425ZrMdVoOMnVyquBNo/FhAOvoSGUyiIUSDdpSwgpiJAH5cVX3W6lOy93mNtPBMk0qxtItYD3b9N7Lut6SCLhL/IGoNmrouOUX3xM8KD8qgnXmUXF0996YK9WxFfZ8HScFVno8kRZdDY4QinqcwZy+FNXBG",
            "serverRandom": "+wVP2U/SMKVkVrggDjNTXFV/",
            "userChallenge": "TLSjYRH2oYw8tW2bq0it0IUb7WIFkCLgF8NTc7-4Zq4",
            "flowType": "Notification",
            "signatureAlgorithm": "rsassa-pss",
            "signatureAlgorithmParameters": {
              "hashAlgorithm": "SHA-512",
              "maskGenAlgorithm": {
                "algorithm": "id-mgf1",
                "parameters": {
                  "hashAlgorithm": "SHA-512"
                }
              },
              "saltLength": 64,
              "trailerField": "0xbc"
            }
          },
          "cert": {
            "value": "MIIFijCCBHKgAwIBAgIJAL3NmQGsd536MA0GCSqGSIb3DQEBCwUAMC8xCzAJBgNVBAYTAkVFMQ4wDAYDVQQKEwVDeWJlcjEQMA4GA1UEAxMHVEMgcm9vdDAeFw0yNTA2MTIxNDM4NDVaFw0yNjA2MTIxNDM4NDVaMIGGMQswCQYDVQQGEwJFRTENMAsGA1UEBAwES2FydTENMAsGA1UEKgwETWF0aTEaMBgGA1UEBRMRUE5PRUUtMzAwMDEwMTAwMDQxJDAiBgNVBAMMG0thcnUsTWF0aSxQTk9FRS0zMDAwMTAxMDAwNDEXMBUGA1UECwwOQVVUSEVOVElDQVRJT04wggMhMA0GCSqGSIb3DQEBAQUAA4IDDgAwggMJAoIDAHPLxyGpzYxygWyvfzju5axnHv2xyiHzSW7adv12BmrWz+W/Hjah1V3OJo3mqG6rG2LI90wNXEbQD2QS/wRI4ksVcdsnmoF5489etoW228YtcGJdIfoUDMW9bz1u4pKdQYHJBnyHo2MmL6q4r2Uyj5comPVRgaL1r16CO+n/Hi9zzomRSQ7bE5zlLaWdRjgeW33hyfy2ZQJAo3MuQ1kxqNEUGLtxhDiEN3kH7M45wikZE1EDV3yNEhrW/xAxmuLCDzY4Y+FfJ+d3H6n+3rhAgk72NfbEtR8AHjV0yj/1KdQt60muSGQ+mDSUcPaUzc9X1QrFvg01l1GcFTkM409AqskZaFFHVUs6/nHItnJO0edQS2/7G0LPPy794QwOUXamlJUZjpmNN39d5SR3WsdonzI8ZEV+PsdAqaHFbSso0fH/59XU0Vlmcy2OvXnff0IYtTWaz1+UT4KrVjPXfbUDuKiaAGKCAaNluH9NxcmVy//qoVui8zGm/swnCJxAMQhdV8Le4gEDWeJiNoUHnypdSgPevccLSxTMXSAnm/MAjXF2XZxefJeaOiVXOGEVr7c+NlMb5wtPlThHcCt9vQoKl+UFIRrSgT7J3u96SU7lFoB3CLwIVYLpmrI498iTpNsqydPGejhWHOpPsK9CSHxrtIeKHExpD2BpUxwJr1/FwwwgwRA0n0uYWk+eo5tJfxFg8FjCTxDbLuVS/DM28DmOyqydcIwkckPXBJeE/ZLHhPEbeLo5z+wCIL/Ao56UFxGrpT+slL80E2EV5ZIXLRH9q0/OzDXEJe/5nOi8pAzE7s4/pLoIlS2gJl8qIFqyrtxkTgRnrbqKftZ+ljrHgEJvUoZ64rSe+Ze4BUpjmPsSFefc5sQNq7QB6vJ860rARStDYwee7c8bZM4pnYYjXbzUATcR74445SYC92q8R6vTRZqGohP9IsrbQrVLMd7k5BEk3QyZAxhBYL1oJJCuB1fQp9orONLg5y9mmBwK/Udb0x4Rzb+sSdnrSDhegdhQbutQZwIDAQABo1IwUDAfBgNVHSMEGDAWgBR34yPLMQW8zhFBhUVMMmjuqyKPxzAdBgNVHQ4EFgQUG8uAz/1qNL+ofmnbWF3IurCBAiMwDgYDVR0PAQH/BAQDAgSwMA0GCSqGSIb3DQEBCwUAA4IBAQA/+yzSFT2Udyol0jspwqidpe0A9YFxJzU8C5i/zyDVQOV+krMS78vBNW83r14YpRxbIHXIjh3HO/oeRseEvVh5yuSYz5lexIjWATKUGOWVZac+gqrTJKuBryqWy7pjAP36knGAaGC17u/Ool/XCUb+K5yZKwsGpzOn9GOx02+0QPVhYy4iC+sJlyUWvLbwNLmf8Nkm00gMPKVUDoDHwiX35wq3ZnuuTOTMMRxx3fszdRKGklt3KytgKGnii+8+Tz3Hh1G6IuRqiMkOpI8dUvi3ywYY72HNjd6ge4Qs2Y2zBxU8XLLBwMYJgwTFoe4JFhsjr32teZZTihlk9Me44dBI",
            "certificateLevel": "QUALIFIED"
          },
          "interactionTypeUsed": "displayTextAndPIN",
          "deviceIpAddress": "203.0.113.34"
        }
        """;

    @SuppressWarnings("checkstyle:LineLength")
    public static final String MID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIDqDCCAy6gAwIBAgIQB9W11BzBABj-0d_AZx6UHzAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjQwNjEyMDY0NTI4WhcNMjkwNjE2MDY0NTI3WjCBlTELMAkGA1UEBhMCRUUxLzAtBgNVBAMMJk1BUlkgw4ROTixPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMSUwIwYDVQQEDBxPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMRIwEAYDVQQqDAlNQVJZIMOETk4xGjAYBgNVBAUTEVBOT0VFLTUxMzA3MTQ5NTYwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWlV1aVSXw6WhagWmFmXE_oe-0R1xZzrHyoiVlgKpGiJ8cwIQLogRGQnWY7NwgQvRHCBmsl99bj57h7SWnd03m6OCAYEwggF9MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1RXzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUweAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNVHQ4EFgQUj8KjnXvGQJCRYOd5LVfPku7QsZwwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMCA2gAMGUCMQCocXWDbBnkM3WEyBdv9Vm0A1MNRv08WrR192dRBcX42Kz5oiH0SdHRJv2ffeuEeSwCMEw2tSA3ClJv233Dl7rIYU_T6UG2NQhvDD5FhnP0umZRmVfAUQ6eVcmU8AhFtNJjwg==";

    private final WireMockExtension wiremock;

    public Cdoc2RpClientMock(WireMockExtension wiremock) {
        this.wiremock = wiremock;
    }

    public void stubSidAuthenticate(UUID sessionId) throws JsonProcessingException {
        wiremock.stubFor(
            WireMock.post(
                urlEqualTo("/sid/authenticate")
            ).willReturn(aResponse()
                .withStatus(HttpStatus.OK_200)
                .withHeader("Content-Type", "application/json")
                .withBody(OBJECT_MAPPER.writeValueAsString(
                    Map.of("sessionID", sessionId.toString())
                ))
            )
        );
    }

    public void stubSidSession(UUID sessionId) {
        wiremock.stubFor(
            WireMock.get(
                urlEqualTo("/sid/session/" + sessionId)
            ).willReturn(aResponse()
                .withStatus(HttpStatus.OK_200)
                .withHeader("Content-Type", "application/json")
                .withBody(SID_SESSION_RESPONSE_OK)
            )
        );
    }

    public void stubMidAuthenticate(UUID sessionId) throws JsonProcessingException {
        wiremock.stubFor(
            WireMock.post(
                urlEqualTo("/mid/authenticate")
            ).willReturn(aResponse()
                .withStatus(HttpStatus.OK_200)
                .withHeader("Content-Type", "application/json")
                .withBody(OBJECT_MAPPER.writeValueAsString(
                    Map.of("sessionID", sessionId.toString())
                ))
            )
        );
    }

    public void stubMidSession(UUID sessionId) {
        wiremock.stubFor(
            WireMock.get(
                urlEqualTo("/mid/session/" + sessionId)
            ).willReturn(aResponse()
                .withStatus(HttpStatus.OK_200)
                .withHeader("Content-Type", "application/json")
                .withBody(MID_SESSION_RESPONSE_OK)
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
