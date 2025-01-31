package ee.cyber.cdoc2.client.smartid;

import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.SmartIdAuthenticationResponse;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.CdocSmartIdClientException;

import java.util.List;

import static ee.cyber.cdoc2.crypto.jwt.InteractionParams.InteractionType.DISPLAY_TEXT_AND_PIN;

/**
 * Client for communicating with the Smart ID client API.
 */
public class SmartIdClient {

    private static final Logger log = LoggerFactory.getLogger(SmartIdClient.class);

    private final SmartIdClientWrapper smartIdClientWrapper;

    public SmartIdClient(SmartIdClientConfiguration conf) {
        smartIdClientWrapper = new SmartIdClientWrapper(conf);
    }

    /**
     * Authentication request to Smart ID client with ETSI semantics identifier.
     * @param semanticsIdentifier ETSI semantics identifier
     * @param authenticationHash Base64 encoded hash function output to be signed
     * @param certificationLevel Level of certificate requested, can either be
     *                           {@code QUALIFIED} or {@code ADVANCED}
     * @param interactionParams Optional  parameters to drive user interaction and to get verification code.
     *                          {@code null} when not in use
     * @return SmartIdAuthenticationResponse object
     */
    public SmartIdAuthenticationResponse authenticate(
        SemanticsIdentifier semanticsIdentifier,
        AuthenticationHash authenticationHash,
        String certificationLevel,
        @Nullable InteractionParams interactionParams
    ) throws CdocSmartIdClientException {
        String errorMsg = "Failed to authenticate Smart ID client request for " + semanticsIdentifier.getIdentifier();

        try {
            return smartIdClientWrapper.authenticate(
                semanticsIdentifier, authenticationHash, certificationLevel,
                    getSIDInteractions(semanticsIdentifier, authenticationHash, certificationLevel, interactionParams)
            );
        } catch (UserAccountNotFoundException ex) {
            throw logNoUserAccountErrorAndThrow(errorMsg);
        } catch (UserRefusedException
                 | UserSelectedWrongVerificationCodeException
                 | SessionTimeoutException
                 | DocumentUnusableException
                 | SmartIdClientException
                 | ServerMaintenanceException ex) {
            log.error(errorMsg);
            throw new CdocSmartIdClientException(errorMsg + ". " + ex.getMessage());
        }
    }

    /**
     * Convert cdoc2 specific InteractionParams to Smart-ID Interaction list. Has same parameters as authenticate, so
     * that this method can be overridden
     * @param semanticsIdentifier ETSI semantics identifier
     * @param authenticationHash  Base64 encoded hash function output to be signed
     * @param certificationLevel  Level of certificate requested, can either be
     *                            {@code QUALIFIED} or {@code ADVANCED}
     * @param interactionParams generic InteractionParams that is used to create Smart-ID {@code Interaction} list
     * @return list of SID Interaction objects
     */
    protected List<Interaction> getSIDInteractions(SemanticsIdentifier semanticsIdentifier,
                                                AuthenticationHash authenticationHash,
                                                String certificationLevel,
                                                @Nullable InteractionParams interactionParams
    ) {
        String displayText200 = (interactionParams == null)
            ? InteractionParams.DEFAULT_DISPLAY_TEXT
            : interactionParams.getDisplayText200();

        String displayText60 = (interactionParams == null)
            ? InteractionParams.DEFAULT_DISPLAY_TEXT
            : interactionParams.getDisplayText60();

        var interactionType = (interactionParams == null)
            ? DISPLAY_TEXT_AND_PIN
            : interactionParams.getInteractionType();

        switch (interactionType) {
            case DISPLAY_TEXT_AND_PIN:
                return  List.of(Interaction.displayTextAndPIN(displayText60));
            case VERIFICATION_CODE_CHOICE:
                return  List.of(Interaction.verificationCodeChoice(displayText60));
            case CONFIRMATION_MESSAGE:
                return List.of(Interaction.confirmationMessage(displayText200));
            case CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE:
                return List.of(Interaction.confirmationMessageAndVerificationCodeChoice(displayText200));
            default:
                log.error("Unknown interaction type {}", interactionType);
                return  List.of(Interaction.displayTextAndPIN(displayText60));
        }
    }


    public AuthenticationIdentity validateResponse(SmartIdAuthenticationResponse authResponse)
            throws CdocSmartIdClientException {
        return smartIdClientWrapper.validateResponse(authResponse);
    }

    private CdocSmartIdClientException logNoUserAccountErrorAndThrow(String requestErrorMsg) {
        String errorMsg = requestErrorMsg + ". There is no such user account";
        log.error(errorMsg);
        return new CdocSmartIdClientException(errorMsg);
    }

}
