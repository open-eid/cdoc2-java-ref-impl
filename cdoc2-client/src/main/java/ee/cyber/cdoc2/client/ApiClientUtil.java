package ee.cyber.cdoc2.client;

import java.util.List;

import org.slf4j.Logger;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.ApiResponse;


/**
 * Utility for handling open API response.
 */
public final class ApiClientUtil {

    public static final int STATUS_CODE_NOT_FOUND = 404;

    private ApiClientUtil() { }

    public static String extractIdFromHeader(
        ApiResponse<Void> response,
        String expectedObject,
        String identificator,
        Logger log
    ) throws ApiException {
        String locationHeaderValue = null;
        if (response.getStatusCode() == 201
            && response.getHeaders() != null
            && response.getHeaders().containsKey("Location")) {

            List<String> locationHeaders = response.getHeaders().get("Location");
            // expect exactly 1 Location header
            if (locationHeaders.size() == 1) {
                locationHeaderValue = locationHeaders.get(0);
            }
        }

        if (locationHeaderValue == null) {
            log.error("Failed to create {}: {}", expectedObject, response.getStatusCode());
            throw new ApiException(response.getStatusCode(), "Failed to create " + expectedObject);
        }
        log.debug("Created {}", locationHeaderValue);
        String[] split = locationHeaderValue.split("/");

        if (split.length == 0) {
            throw new IllegalArgumentException(identificator + " not present in location header");
        }
        return split[split.length - 1];
    }

}
