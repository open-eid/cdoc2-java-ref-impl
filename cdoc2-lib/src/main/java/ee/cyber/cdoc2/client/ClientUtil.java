package ee.cyber.cdoc2.client;

import java.io.IOException;

import org.slf4j.Logger;

import ee.cyber.cdoc2.client.api.ApiException;

final class ClientUtil {
    private ClientUtil() {
        // utility class
    }

    static ExtApiException wrapApiException(String context, ApiException ex, Logger log) {
        String detail = switch (ex.getCode()) {
            case 400 -> "Bad request — check the parameters";
            case 401 -> "Unauthorized — missing or invalid auth ticket";
            case 403 -> "Forbidden — authentication failed";
            case 404 -> "Not found — record missing or recipient ID mismatch";
            default -> "Unexpected server response";
        };
        log.error("{}: {} (HTTP {}) — {}", context, detail, ex.getCode(), ex.getMessage());
        return new ExtApiException(
            context + ": " + detail + " (HTTP " + ex.getCode() + ") — " + ex.getMessage(), ex
        );
    }

    static ExtApiException wrapNetworkException(Exception ex, String serverUrl, Logger log) {
        log.error("{} {}: {}", "Failed to connect to authentication server",
            serverUrl,
            ex.getMessage(),
            ex
        );
        String detail = (ex.getCause() instanceof IOException)
            ? ex.getCause().getMessage()
            : ex.getMessage();
        return new ExtApiException(
            "Failed to connect to authentication server" + " " + serverUrl + ": " + detail,
            ex
        );
    }
}
