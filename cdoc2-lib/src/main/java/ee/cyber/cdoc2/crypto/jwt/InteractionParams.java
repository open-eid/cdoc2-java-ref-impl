package ee.cyber.cdoc2.crypto.jwt;

import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import jakarta.annotation.Nullable;

import java.util.LinkedList;
import java.util.List;

/**
 * Smart-ID and Mobile-ID interaction parameters.
 * Optional parameters to drive user interaction and to get verification code.
 * Current implementation is a base, extend this to support more Interaction. Even more control can be achieved by
 * overriding {@link ee.cyber.cdoc2.client.smartid.SmartIdClient#getSIDInteractions(SemanticsIdentifier,
 * AuthenticationHash, String, InteractionParams)} method
 */
public class InteractionParams {

    /**
     * Smart-ID interaction type. Mobile-ID will always use text and pin.
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file
     * #31-uc-x-interaction-choice-realization">Smart-ID interaction choice</a>
     */
    public enum InteractionType {
        DISPLAY_TEXT_AND_PIN,
        CONFIRMATION_MESSAGE,
        VERIFICATION_CODE_CHOICE,
        CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE
    }


    /** Default text for Smart-ID. Max length 60 chars. Default text for MID is defined in mobile-id.properties */
    public static final String DEFAULT_DISPLAY_TEXT = "Authenticate to decrypt CDOC2 document";

    /** Default text for SID/MID, when document is defined */
    public static final String DEFAULT_DISPLAY_TEMPLATE = "Authenticate to decrypt CDOC2 document %s";

    protected InteractionType interactionType;
    /**
     * Document that is decrypted. Or some other identifier that is known to user to notify what is decrypted.
     */
    protected @Nullable String document;

    protected String displayText;

    /** MID language {@link ee.sk.mid.MidLanguage} */
    private String language;

    /** MID {@link ee.sk.mid.MidDisplayTextFormat} */
    private String encoding;

    /** Listeners that are interested of receiving verification code */
    List<AuthListener> listeners = new LinkedList<>();

    protected InteractionParams(InteractionType type, @Nullable String document, String displayText) {
        this.interactionType = type;
        this.document = document;
        this.displayText = displayText;
    }

    /**
     * When supported, then "First screen combines text and Verification Code choice. Second screen is for PIN."
     */
    public static InteractionParams displayTextAndVCCForDocument(String document) {
        return new InteractionParams(InteractionType.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE,
            document,
            String.format(DEFAULT_DISPLAY_TEMPLATE, document)
        );
    }

    /**
     * Simplest interaction with text and pin and default text
     */
    public static InteractionParams displayTextAndPin() {
        return new InteractionParams(InteractionType.DISPLAY_TEXT_AND_PIN, null, DEFAULT_DISPLAY_TEXT);
    }

    public static InteractionParams displayTextAndPin(String text) {
        return new InteractionParams(InteractionType.DISPLAY_TEXT_AND_PIN, null, text);
    }

    /** Get text displayed. If text is longer than 60 chars, will be capped to 60 chars */
    public String getDisplayText60() {
        return getDisplayText(60);
    }

    /** Get text displayed capped to length
     * @param length text will be capped to length
     * @return displayText
     */
    public String getDisplayText(int length) {
        if (displayText.length() > length) {
            return displayText.substring(0, length);
        } else {
            return displayText;
        }
    }

    /** Overwritten MID language */
    public @Nullable String getLanguage() {
        return language;
    }

    /**
     * Overwrite configured language of MobileIdClient
     * Set enum value using valueOf() for MidLanguage
     */
    public void setLanguage(String language) {
        this.language = language;
    }

    /** Overwritten MID encoding */
    public String getEncoding() {
        return encoding;
    }

    /** Overwrite configured {@link ee.sk.mid.MidDisplayTextFormat} */
    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }


    /** Get text displayed. If text is longer than 200 chars, will be capped to 200 chars */
    public String getDisplayText200() {
        return getDisplayText(200);
    }

    /** Get full length display text */
    public String getDisplayTextFull() {
        return displayText;
    }

    /** Get Smart-ID interaction type
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file
     * #31-uc-x-interaction-choice-realization">Smart-ID interaction</a>
     **/
    public InteractionType getInteractionType() {
        return interactionType;
    }


    public @Nullable String getDocument() {
        return document;
    }

    /** Add AuthListener that gets notified with verification code when authentication is requested*/
    public InteractionParams addAuthListener(AuthListener listener) {
        listeners.add(listener);
        return this;
    }

    public InteractionParams removeAuthListener(AuthListener listener) {
        listeners.remove(listener);
        return this;
    }

    /** Called by MID/SID JWSSigner when hash from signingInput was calculated and verification code can be provided */
    public void notifyAuthListeners(AuthEvent event) {
        for (AuthListener listener : listeners) {
            listener.authStarted(event);
        }
    }
}
