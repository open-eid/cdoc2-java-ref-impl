package ee.cyber.cdoc2.client.mobileid;

import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidAuthenticationResponseValidator;
import ee.sk.mid.MidAuthenticationResult;
import ee.sk.mid.MidClient;
import ee.sk.mid.MidHashToSign;
import ee.sk.mid.exception.MidDeliveryException;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.exception.MidInvalidUserConfigurationException;
import ee.sk.mid.exception.MidMissingOrInvalidParameterException;
import ee.sk.mid.exception.MidNotMidClientException;
import ee.sk.mid.exception.MidPhoneNotAvailableException;
import ee.sk.mid.exception.MidSessionNotFoundException;
import ee.sk.mid.exception.MidSessionTimeoutException;
import ee.sk.mid.exception.MidUnauthorizedException;
import ee.sk.mid.exception.MidUserCancellationException;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;

import java.util.Arrays;
import java.util.List;

import ee.cyber.cdoc2.exceptions.CdocMobileIdClientException;

/**
 * Mobile-ID Client wrapper
 */
public class MobileIdClientWrapper {

    private final MidClient midClient;
    private final MidAuthenticationResponseValidator responseValidator;

    /**
     * Constructor for Mobile-ID Client wrapper
     * @param midClient Mobile-ID client
     */
    public MobileIdClientWrapper(MidClient midClient) {
        this.midClient = midClient;
        responseValidator = new MidAuthenticationResponseValidator(midClient.getTrustStore());
    }

    /**
     * Authentication request to {@code /authentication}
     * @param request MID authentication request
     * @param authenticationHash Base64 encoded hash function output to be signed
     * @return MidAuthentication object that contains MidSignature and Certificate
     * @throws CdocMobileIdClientException if authentication fails
     */
    public MidAuthentication authenticate(
        MidAuthenticationRequest request,
        MidHashToSign authenticationHash
    ) throws CdocMobileIdClientException {

        try {
            MidAuthenticationResponse authResponse
                = midClient.getMobileIdConnector().authenticate(request);

            MidSessionStatus sessionStatus = midClient
                .getSessionStatusPoller()
                .fetchFinalAuthenticationSessionStatus(authResponse.getSessionID());

            MidAuthentication midAuthentication
                = midClient.createMobileIdAuthentication(sessionStatus, authenticationHash);

            //Other responses beside "OK" https://github.com/SK-EID/MID?tab=readme-ov-file#338-session-end-result-codes
            if (midAuthentication.getResult().equals("OK")) {
                validateAuthenticationAndReturnIdentity(midAuthentication); // throws CdocMobileIdClientException
                return midAuthentication;
            }

            throw new CdocMobileIdClientException("Mobile ID authentication session has failed with "
                + midAuthentication.getResult());

        } catch (MidUserCancellationException
                 | MidNotMidClientException
                 | MidSessionTimeoutException
                 | MidPhoneNotAvailableException
                 | MidDeliveryException
                 | MidInvalidUserConfigurationException
                 | MidSessionNotFoundException
                 | MidMissingOrInvalidParameterException
                 | MidUnauthorizedException
                 | MidInternalErrorException e) {
            throw new CdocMobileIdClientException("Mobile ID authentication has failed.", e);
        }
    }

    public void validateAuthenticationAndReturnIdentity(
        MidAuthentication authentication
    ) throws CdocMobileIdClientException {

        MidAuthenticationResult authResult = responseValidator.validate(authentication);
        List<String> authErrors = authResult.getErrors();
        if (authResult.isValid() && authErrors.isEmpty()) {
            return;
        }

        throw new CdocMobileIdClientException(
            "Mobile ID authentication response validation has failed with errors: "
            + Arrays.toString(authErrors.toArray())
        );
    }

}
