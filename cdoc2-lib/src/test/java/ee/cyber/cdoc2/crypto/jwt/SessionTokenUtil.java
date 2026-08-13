package ee.cyber.cdoc2.crypto.jwt;

import static ee.cyber.cdoc2.AuthClientMock.SESSION_TOKEN_BASE64URL;
import static ee.cyber.cdoc2.AuthClientMock.SID_SIGNING_CERTIFICATE_BASE64URL;

public final class SessionTokenUtil {

    private SessionTokenUtil() {
    }

    public static SessionToken createSessionToken() {
        return new SessionToken(SESSION_TOKEN_BASE64URL, SID_SIGNING_CERTIFICATE_BASE64URL);
    }
}
