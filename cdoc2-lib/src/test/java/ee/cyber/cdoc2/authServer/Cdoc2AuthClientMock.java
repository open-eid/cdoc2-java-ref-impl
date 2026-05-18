package ee.cyber.cdoc2.authServer;

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


public class Cdoc2AuthClientMock {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String DEFAULT_VERIFICATION_CODE = "1234";

    @SuppressWarnings("checkstyle:LineLength")
    public static final String SESSION_TOKEN_BASE64URL = "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6IlFzZnRRdThWRGNyaW1xaGhnc1AvQkNITGIrQkNkaFFLUU1KUStuSVlYZ2kyd2VjSEhhTlAwckFTTTBuaGdqWWJSQUVTZEx5c3JrYzEzRWJlMEU2dUNnPT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiZ01MeEJjbUNic0lmSnJWQk9ZNW9qZXpTMVdqS0srM1dnRkh3aFVJTTJpU0hwVTF3KytLZk1xdjVyckNkOHdxVDJXTmJKYVMvL0lHalhFN2JxRmZxMUVzR0NvWng3WXF4N0NyQys1OFh0c3F5VENlbnN6bGN1aW10ak1CQ0RYT2JSRCtOMS9iTVowTktBeTZpeXlQcmlNS0ZCdm45YUE2N0FkUnVxRyttUDI2M0VLNXJGZ1F6dU5JZ0FiK0Y3TVNMU1ZweXJFMEpWbUtnUWpDa2d1U1ZNTWRSaitTNlpHQVpIeG9ValFUYWttcmFiazlQT1QvNWZ4N3N4bTV5aFkwelJOTE4rRGxNUG1pdEUraG1DM0dDR3hqZDdNbVI1eFJQNGJLWDB5SmFpSVdVaWY3Q0I3VTJCekplZFl2aE9xOXhDTUg5Y1hrR2MrbnBKWWpZUG9VWnlOeDBHTzZVa0MxaEx0ZmRUSlQ0RktMWFoxOVk2TmNhS2JKTDZZY0JaRDdqUFNvWFNTMG5Va1p0dGlTN3BGVSsvYzZUNXFHRjRpT2NVOElxVFNERlFNNkpPSnRzMEUwb3BWMHlMeGxHZ2JXNjFqNmltU29HcGxGLzdrZFladkxSZkZMYXd2Sk1WWnQ3V0F6TEI0aVk2Rk12VzR3dFc3bWQ5cFBsaVpoZGJmOTJORHJqUS9GYnUwQUVqRm8xemdXTi9hSnJyZTNkVHYxM3JMRHBDOHRxRmlCemJKSWNSMjlYYUtIdVR3K05qcW9qTnB6SkV0RjgvY2I4RXpQREpxbHY0Qjl2aGY2UTVacWZ1VFJ2cTFWam5vcjEyejZydGJXMVJCMU52MjlwRVpUNWpLSUVMKy9XVjhlNXJpcy85S2dvSGhCZGphUXkrSk15d1BtemtnQnhXSkhBUi92T0wyR3ZucGNFMTZGem5ubEh1a0Q4Y21JK3NVTlZ6SXorbXBVVGJSM2NNVnRzQnpJbC9UQndYa0Y2RU5OTVhvZzFOQmo1akZjMGs3bGJnQWk0SVR5OWEySis3c1ZtWHpLWTJsWEtIU2pick9kRVZhRW9qaFhHSy9aWURHcUs1UzNKSEJZR1VVUUt4NmxkL2JRb2Y4a3RQZEZ5S3RWeDRhbnE5TXN5L2NFV2ZreU9PcUd1YlQyblh6UStqb2tZZkROdFdKNHZmS1hVQzRRVjRNNCswd3o4M04zU25QNkZiVlgvUUZUeHZQT1hhbGY1Y0dRK3N1NU9IN3JHWVZ5NzVLbS83TXVNdnlYRWFTQTJlUUZIbWJIeW14Slk3cWprODVxbXFVTjdkcStTb2dwT2hCMHFiS290a1lrRUdJZW5BdmJSR1hCbFoxYXd1ZWdJRUNvUCIsInNlcnZlclJhbmRvbSI6Ik56dHFUcWQxYVQ4VW1wYXdEMi9QbStuSyIsInVzZXJDaGFsbGVuZ2UiOiJ2YkRfTkdQWUJsYXVxUWw2SnNlZkxQUmFQMEw2X1hXMDBiZWtDV2J6bWFzIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyJuM0RTeFlUUTNpZmxPMktqZDZjSHNXWHo4aUxSYnZ2Njc1WkkxRWtpbmhvIl0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3NzcwNTMwMjcsImlhdCI6MTc3Njk2NjYyNywiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.15W7YiGj4zetAhvRV4s3yC_fa4v_-OoZzvljt5D30t1lrDgD6aLozwtWfgBIQ5OaL9w15Gl3_UvHj4gXgZPxCA~WyJKZTVNaG9haVpFOE9EM2JNOVR1Z0dRIiwiYXVkIixbeyIuLi4iOiJUVGdBYkJqNURWS1MtUVNWUVVLZnZNU1NqbEJDeU04QlFNVTJWVmtpR1NRIn0seyIuLi4iOiIyYWkxUllaMUhuVlRiVUZuc0tsbWQ0THZkOXBMdWk1aDd0WDJ3VDhDbWFRIn1dXQ~WyJrMmFDOTVEd3ItY1FhYWxfTHBxV3NBIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mi9zZXNzaW9uX25vbmNlL0dFYnRxTWZqdjF0Z19mOFpFQ09QckEiXQ~WyI5aTFmSVF0WkFZWFVTMzVxeXVfeW9BIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0My9zZXNzaW9uX25vbmNlL2p0X0tEUHFGdEgyWVQtTTk2VHNDeWciXQ~";

    @SuppressWarnings("checkstyle:LineLength")
    public static final String SESSION_TOKEN_NONCE_LOCALHOST_7600_BASE64URL =
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6IkxkeUczVy9EZEhIdmc5MTFxbUR2c3FacFNzUzZKdm1BZFVQK1BWcXJML080N3pKb253N2lWWElIRmZoZ0swSkpqcmN2WWtpREplOTNKMGFlZUNjNDR3PT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiYU16OUtZN09oUysvaHdzSmpDN1J0VDdwWVNwZHpDNG04V1ZidXJqdlIzS21BREZVSXpQbHhQR2dvbjMvcDU0LzVBWEQ1YjZPZUNZUDlMM3lTRGo5eEw0N3loaDd5UnY1RUYvY3g5UEpVZVdTVmErbWZydnZlMDV3TGZjZWtyYndINkMwRzR5V2tIa2lIam5WV3hEYlR2OU5BYi81Q3JLdlp6VjRweDlqOFgrYzdNT1E0dmtVcUZubHhUdEhHNytIdEJjRlNhZ2ZsVnUzYm5PeWFrczBEeXJhdFdEQnIxMHBOZ3hCUzJXQkk5S3BtclZWOW9BT0Ezb21FK012R3JYVXI1SG11b0R2UTlWTjE1YjI1K3ljZTFJYTgrb3lNMVdPQUJjSmlkVHlxVUwzdmhxUlN3UjN3SUN1YXk1d0pYaHN4MVcrVnlOQ0ZuQmUvS1JJUWxMV3JlWWtaUDZqUXg0b2QvNFJvUEFLVG0xQWZ6QWFQVjVCOXhLanB3VmZITnhNVisxMVlYM2M3TWhqdmcvTFl5S0tVQUpUWUJDd25xdUhDUDhiZzNjMWtUQmVDb1B2NTFDTEozU1cwcHFCanVHNzVYQ1l0MTViVVJaSDU4VnR2eEVGNzlDZitxOVRTYjNncmtnYkVEV0tvN0tPOUlpMk5QZFVBOVdNTWNnSEZ4eGtxSjVOdmRHK0FNRUNPNmpmOFdDNWp5RWNRVk04ZHUvN1kxeGpNdVNHbzZKSVdOaU9lcWVQUEU0N1k2U0FOanVQeEx4YnNZeHpRTlJkOGtyRnVuN21pTG04YVF0bmdqTWkxdk9XVnBPdEpFNTEvcG4wc2JIMW1HTitnUUZTZzYraWtxd2hKSVNiQVlUZ3laOFJmd0pRdTdWSWFMRHpCUjE3Njh2U3dkeEtCcVlqQzRTZ2hwWmFjMUlsczBlUlpRVlJDSlhCVitmREgzVWd3NVZTZzlWWU1LankvUFZ5RU52b2Y4WFNJb3phRlRKQ2VCdVhhVXlmTmg4SitUcEU1WlFYY0orUE8rVCtPTmVGNUtXRjZmSzBnRWtLcThuYUtnR3RWeTIyeC93TGZWVjBWVE1uei96L3NuMkpINXZCMmVwUHBBdUd2akVuM1pzR20vbVFxMlFqWExGcFFEYXFWYnlmSzJjWU1lMmJ0WGFta2ZTRHlYeTZuMmoxMjFYMWxZZFR5aWdTd1FOR3d3ZUdDWFQxaHBUOU9WbFVGSWkrcVB4K0toV3hYTWFtdHU3am1waWFEU0V0WU5wZGg3TG1rT0lCRGw4Y1UxR1BtRFJWTVVCRVZvN1U5SC8zUllUZWhSN0RTaWhoeG9DZzEyNjU4dmdSQy9qaG1BQ2VvMnNTN1VQTiIsInNlcnZlclJhbmRvbSI6IjZsQTRZdXc5anFpbEVaZ25hb3JHcG5mUCIsInVzZXJDaGFsbGVuZ2UiOiJWZnZnTUdRdS1IZW9DMmRjT0o4N2FXR3hQV1hmXzdZOXZCNG5uUG1vczhRIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyJkQ196R21paTJRWWpWb3RORkt1dmZXRFpNUWpYNzY3dnlQVV9JUF93R01nIl0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3Nzg5MjE1NTQsImlhdCI6MTc3ODgzNTE1NCwiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.LoAVERzVgqer_7HrIpGr0N0Tjr_93jyvTfoDBeF-dkn1OZXYKB95Ebg3PDhTG28PM1-NfrrloUopgKsxyF4GQQ~WyJ1TEF5Q1NFNGpuRWpZQndQbHl6RllBIiwiYXVkIixbeyIuLi4iOiI5X1dhLVY5WHRtWmR2dUVrdjlBYTRLQlpia3g3YWI3Y3p6eGJZVEZrWUQ4In1dXQ~WyJXQ1djYUtfWHI4bzVCNFczcEpCMzJnIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzYwMC9zZXNzaW9uX25vbmNlL0o2aDFZQlhrc3VOQnROeVpwSWpSclEiXQ~";
    @SuppressWarnings("checkstyle:LineLength")
    public static final String SID_SIGNING_CERTIFICATE_BASE64URL = "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";

    private final WireMockExtension wiremock;

    public Cdoc2AuthClientMock(WireMockExtension wiremock) {
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

    public void stubForAuthStatus(UUID authProccessUuid) throws JsonProcessingException {
        Map<String, Object> response = Map.of(
            "status", "COMPLETE",
            "endResult", "OK",
            "sessionToken", SESSION_TOKEN_NONCE_LOCALHOST_7600_BASE64URL,
            "signingCertificate", SID_SIGNING_CERTIFICATE_BASE64URL
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
