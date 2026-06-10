package ee.cyber.cdoc2.crypto.jwt;

import jakarta.annotation.Nullable;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.authserver.AuthProcessData;
import ee.cyber.cdoc2.client.authserver.Cdoc2AuthClient;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.client.model.AuthProcessStatusResponse;
import ee.cyber.cdoc2.crypto.KeyShareUri;

import static ee.cyber.cdoc2.auth.SessionTokenDisclosureHelper.discloseAudByClaimValue;


public class SessionToken {
    private static final Logger log = LoggerFactory.getLogger(SessionToken.class);
    Cdoc2AuthClient cdoc2AuthClient;

    private String sessionTokenBase64Url;
    private String signingCertificate;

    public SessionToken(
        Cdoc2AuthClient cdoc2AuthClient,
        String recipient,
        @Nullable String mobileNumber
    ) {
        this.cdoc2AuthClient = cdoc2AuthClient;

        create(recipient, mobileNumber);
    }

    // package-private, for tests only
    public SessionToken(
        String sessionTokenStr,
        String signingCertificateStr
    ) {
        this.sessionTokenBase64Url = sessionTokenStr;
        this.signingCertificate = signingCertificateStr;
    }

    public String getSessionToken(KeyShareUri shareUri) {
        var sessionToken =
            discloseAudByClaimValue(this.sessionTokenBase64Url, shareUri.serverBaseUrl());
        if (sessionToken == null) {
            throwSessionTokenDisclosureError(shareUri.serverBaseUrl());
        }
        return sessionToken;
    }

    public String getSessionToken(String claimValue) {
        var sessionToken = discloseAudByClaimValue(this.sessionTokenBase64Url, claimValue);
        if (sessionToken == null) {
            throwSessionTokenDisclosureError(claimValue);
        }
        return sessionToken;
    }

    private void create(
        String recipient,
        @Nullable String mobileNumber
    ) {
        var identity = new AuthIdentity();
        identity.setIdentifier(recipient);
        identity.setMobileNr(mobileNumber);

        AuthProcessData authProcess = startAuth(identity);
        AuthProcessStatusResponse status = getAuthStatus(authProcess.uuid());
        log.debug("Final auth process {} status: {}", authProcess.uuid(), status);
        if (!"COMPLETE".equals(status.getStatus())) {
            throw new RuntimeException("Auth process did not complete successfully");
        }

        this.sessionTokenBase64Url = status.getSessionToken();
        this.signingCertificate = status.getSigningCertificate();
    }

    private AuthProcessData startAuth(AuthIdentity identity) {
        try {
            return cdoc2AuthClient.startAuth(identity);
        } catch (ExtApiException e) {
            throw new RuntimeException("Failed to start authentication process", e);
        }
    }

    private AuthProcessStatusResponse getAuthStatus(UUID uuid) {
        try {
            return cdoc2AuthClient.getAuthProcessStatus(uuid);
        } catch (ExtApiException e) {
            throw new RuntimeException("Failed to retrieve authentication process status", e);
        }
    }

    public String getSigningCertificate() {
        return signingCertificate;
    }

    private void throwSessionTokenDisclosureError(String claimValue) {
        var message = String.format(
            "Failed to create the disclosed session token, the claim value '%s' is missing from the session token",
            claimValue
        );
        log.error(message);
        throw new RuntimeException(message);
    }
}
