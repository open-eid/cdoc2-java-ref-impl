package ee.cyber.cdoc2.crypto.jwt;

import jakarta.annotation.Nullable;

import java.util.LinkedList;
import java.util.List;


/**
 * Smart-ID and Mobile-ID interaction parameters.
 * Optional parameters to drive user interaction and to get verification code.
 * Current implementation is a base, extend this to support more Interaction.
 */
public class InteractionParams {

    /**
     * Smart-ID interaction type. Mobile-ID will always use text and pin.
     *
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file
     * #31-uc-x-interaction-choice-realization">Smart-ID interaction choice</a>
     */
    public enum InteractionType {
        DISPLAY_TEXT_AND_PIN,
        CONFIRMATION_MESSAGE,
        VERIFICATION_CODE_CHOICE,
        CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE
    }

    /**
     * ISO 639-1 language codes
     */
    public enum InteractionLanguage {
        ET,
        EN,
        RU,
        LT
    }

    /**
     * Default text for SID/MID when no document defined.
     */
    public static final String DEFAULT_DISPLAY_TEXT = "Authenticate to decrypt CDOC2 document";

    /**
     * Default text for SID/MID, when document is defined
     */
    public static final String DEFAULT_DISPLAY_TEMPLATE = "Authenticate to decrypt CDOC2 document %s";

    protected InteractionType interactionType;

    /**
     * Document that is decrypted. Or some other identifier that is known to user to notify what is decrypted.
     */
    private final @Nullable String document;

    /**
     * text to be displayed on the user's device during authentication token creation
     */
    protected String displayText;

    /**
     * language for server component interactions with the user. This includes session token
     * creation via auth-server and part of the MID interaction messaging.
     */
    private final @Nullable InteractionLanguage interactionLanguage;

    /**
     * MID {@link ee.sk.mid.MidDisplayTextFormat}
     */
    private String encoding;

    /**
     * Listeners that are interested of receiving verification code
     */
    List<AuthListener> listeners = new LinkedList<>();

    protected InteractionParams(
        InteractionType type,
        @Nullable String document,
        @Nullable InteractionLanguage interactionLanguage,
        @Nullable String displayText
    ) {
        this.interactionType = type;
        this.document = document;
        this.interactionLanguage = interactionLanguage;
        this.displayText = displayText;
    }

    /**
     * When supported, then "First screen combines text and Verification Code choice. Second screen is for PIN."
     */
    public static InteractionParams displayTextAndVCCForDocument(
        String document,
        InteractionLanguage interactionLanguage,
        String displayText
    ) {
        return new InteractionParams(
            InteractionType.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE,
            document,
            interactionLanguage,
            displayText == null
                ? String.format(DEFAULT_DISPLAY_TEMPLATE, document)
                : displayText
        );
    }

    /**
     * Simplest interaction with text and pin
     */
    public static InteractionParams displayTextAndPin(
        InteractionLanguage interactionLanguage,
        String displayText
    ) {
        return new InteractionParams(
            InteractionType.DISPLAY_TEXT_AND_PIN,
            null,
            interactionLanguage,
            displayText == null
                ? DEFAULT_DISPLAY_TEXT
                : displayText
        );
    }

    /**
     * Get text displayed. If text is longer than 60 chars, will be capped to 60 chars
     */
    public String getDisplayText60() {
        return getDisplayText(60);
    }

    /**
     * Get text displayed capped to length
     *
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

    /**
     * Overwritten MID encoding
     */
    public String getEncoding() {
        return encoding;
    }

    /**
     * Overwrite configured {@link ee.sk.mid.MidDisplayTextFormat}
     */
    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    /**
     * Get text displayed. If text is longer than 200 chars, will be capped to 200 chars
     */
    public String getDisplayText200() {
        return getDisplayText(200);
    }

    /**
     * Get full length display text
     */
    public String getDisplayTextFull() {
        return displayText;
    }

    /**
     * Get Smart-ID interaction type
     *
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file
     * #31-uc-x-interaction-choice-realization">Smart-ID interaction</a>
     **/
    public InteractionType getInteractionType() {
        return interactionType;
    }


    public @Nullable String getDocument() {
        return document;
    }

    /**
     * Add AuthListener that gets notified with verification code when authentication is requested
     */
    public InteractionParams addAuthListener(AuthListener listener) {
        listeners.add(listener);
        return this;
    }

    public InteractionParams removeAuthListener(AuthListener listener) {
        listeners.remove(listener);
        return this;
    }

    /**
     * Called by MID/SID JWSSigner when hash from signingInput was calculated and verification code can be provided
     */
    public void notifyAuthListeners(AuthEvent event) {
        for (AuthListener listener : listeners) {
            listener.authStarted(event);
        }
    }

    public @Nullable InteractionLanguage getInteractionLanguage() {
        return interactionLanguage;
    }
}
