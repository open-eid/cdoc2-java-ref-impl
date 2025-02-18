package ee.cyber.cdoc2.crypto.jwt;

import java.util.EventListener;


public interface AuthListener extends EventListener {
    /** Notify that authentication request was started */
    void authStarted(AuthEvent event);
}
