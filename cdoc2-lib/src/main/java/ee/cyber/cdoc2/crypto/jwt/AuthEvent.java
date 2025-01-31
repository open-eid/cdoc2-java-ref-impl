package ee.cyber.cdoc2.crypto.jwt;

import jakarta.annotation.Nullable;

import java.util.EventObject;

/**
 * Smart-ID or Mobile-ID authentication event. Provides property to get verification code that is displayed
 * on user device.
 */
public class AuthEvent extends EventObject {

    private final String document;
    private final String verificationCode;

    /**
     * @param source The object on which the Event initially occurred.
     * @param verificationCode
     * @param document document being decrypted or some other identifier that identifier object being decrypted.
     *                 May be null, when document is not known.
     */
    public AuthEvent(Object source, String verificationCode, @Nullable String document) {
        super(source);
        this.document = document;
        this.verificationCode = verificationCode;
    }

    /** Get verification code generated for Smart-ID or Mobile-ID */
    public String getVerificationCode() {
        return this.verificationCode;
    }

    /** Get cdoc2 document that is being decrypted. */
    public @Nullable String getDocument() {
        return this.document;
    }
}
