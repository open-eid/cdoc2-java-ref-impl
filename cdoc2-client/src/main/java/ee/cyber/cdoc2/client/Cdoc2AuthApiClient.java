package ee.cyber.cdoc2.client;

import jakarta.annotation.Nonnull;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.Cdoc2AuthApi;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.client.model.AuthProcessStatusResponse;
import ee.cyber.cdoc2.client.model.WellKnownResponse;

public class Cdoc2AuthApiClient {
    /**
     * Matches the UUID at the end of a Location header like /auth/status/{authProcessUuid}
     */
    private static final Pattern AUTH_PROCESS_UUID_PATTERN =
        Pattern.compile("/auth/status/([^/]+)$");

    private final Cdoc2AuthApi authApi;

    public Cdoc2AuthApiClient(Cdoc2AuthApi authApi) {
        this.authApi = authApi;
    }

    public static AuthClientBuilder builder() {
        return new AuthClientBuilder();
    }

    /**
     * Starts an authentication process for the given identity.
     *
     * @param authIdentity the identity to authenticate
     * @return the {@code authProcessUuid} extracted from the {@code Location} response header
     * and the verification code from the requests body.
     * @throws ApiException if the API call fails or the UUID cannot be extracted
     */
    public AuthProcessData startAuth(@Nonnull AuthIdentity authIdentity) throws ApiException {
        var response = authApi.startAuthWithHttpInfo(authIdentity);

        String location = extractLocation(response.getHeaders());
        UUID uuid = extractUuidFromLocation(location);

        String vc = response.getData().getVc();

        return new AuthProcessData(uuid, vc);
    }

    /**
     * Get auth process status
     *
     * @param authProcessUuid the UUID returned by {@link #startAuth(AuthIdentity)}
     * @return the current {@link AuthProcessStatusResponse}
     * @throws ApiException if the API call fails (e.g. 400, 401, 404)
     */
    public AuthProcessStatusResponse getAuthProcessStatus(@Nonnull UUID authProcessUuid)
        throws ApiException {
        return authApi.getAuthProcessStatus(String.valueOf(authProcessUuid));
    }

    /**
     * Retrieves the server's well-known JWKS signing-key information.
     *
     * @return {@link WellKnownResponse} containing the server's signing keys
     * @throws ApiException if the API call fails
     */
    public WellKnownResponse getWellKnown() throws ApiException {
        return authApi.getWellKnown();
    }

    private static String extractLocation(
        Map<String, List<String>> headers) throws ApiException {

        for (var entry : headers.entrySet()) {
            if ("Location".equalsIgnoreCase(entry.getKey())) {
                java.util.List<String> values = entry.getValue();
                if (values != null && !values.isEmpty()) {
                    return values.get(0);
                }
            }
        }
        throw new ApiException(
            "Response did not contain 'Location' header"
        );
    }

    private static UUID extractUuidFromLocation(String location) throws ApiException {
        if (location == null || location.isBlank()) {
            throw new ApiException(
                "Location header is blank; cannot extract authProcessUuid");
        }

        Matcher matcher = AUTH_PROCESS_UUID_PATTERN.matcher(location);
        if (!matcher.find()) {
            throw new ApiException(
                "Location header does not match expected pattern "
                    + AUTH_PROCESS_UUID_PATTERN.pattern() + ": " + location);
        }

        String uuidString = matcher.group(1);

        try {
            return UUID.fromString(uuidString);
        } catch (IllegalArgumentException e) {
            throw new ApiException(
                "Extracted authProcessUuid is not a valid UUID: " + uuidString);
        }
    }

    /**
     * CDOC2 Authentication process data
     *
     * @param uuid
     * @param verificationCode
     */
    public record AuthProcessData(
        UUID uuid,
        String verificationCode
    ) {
    }
}
