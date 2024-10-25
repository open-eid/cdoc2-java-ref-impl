package ee.cyber.cdoc2.client.smartid;

import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.SmartIdAuthenticationResponse;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.exceptions.SmartIdClientException;


/**
 * Client for communicating with the Smart ID client API.
 */
public class SmartIdClient {

    private static final Logger log = LoggerFactory.getLogger(SmartIdClient.class);

    private final SmartIdClientWrapper smartIdClientWrapper;

    public SmartIdClient() throws ConfigurationLoadingException {
        smartIdClientWrapper = new SmartIdClientWrapper();
    }

    public SmartIdClient(SmartIdClientConfiguration conf) {
        smartIdClientWrapper = new SmartIdClientWrapper(conf);
    }

    /**
     * Authentication request to Smart ID client with ETSI semantics identifier.
     * @param semanticsIdentifier ETSI semantics identifier
     * @param authenticationHash  Base64 encoded hash function output to be signed
     * @param certificationLevel  Level of certificate requested, can either be
     *                            {@code QUALIFIED} or {@code ADVANCED}
     * @return SmartIdAuthenticationResponse object
     */
    public SmartIdAuthenticationResponse authenticate(
        SemanticsIdentifier semanticsIdentifier,
        AuthenticationHash authenticationHash,
        String certificationLevel
    ) throws SmartIdClientException {
        String errorMsg = "Failed to authenticate Smart ID client request for " + semanticsIdentifier.getIdentifier();

        try {
            return smartIdClientWrapper.authenticate(
                semanticsIdentifier, authenticationHash, certificationLevel
            );
        } catch (UserAccountNotFoundException ex) {
            throw logNoUserAccountErrorAndThrow(errorMsg);
        } catch (UserRefusedException
                 | UserSelectedWrongVerificationCodeException
                 | SessionTimeoutException
                 | DocumentUnusableException
                 | ServerMaintenanceException ex) {
            log.error(errorMsg);
            throw new SmartIdClientException(errorMsg + ". " + ex.getMessage());
        }
    }

    private SmartIdClientException logNoUserAccountErrorAndThrow(String requestErrorMsg) {
        String errorMsg = requestErrorMsg + ". There is no such user account";
        log.error(errorMsg);
        return new SmartIdClientException(errorMsg);
    }

}
