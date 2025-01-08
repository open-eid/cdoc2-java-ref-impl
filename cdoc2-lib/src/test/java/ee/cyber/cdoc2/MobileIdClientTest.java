package ee.cyber.cdoc2;

import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidAuthenticationIdentity;
import ee.sk.mid.exception.MidDeliveryException;
import ee.sk.mid.exception.MidInvalidUserConfigurationException;
import ee.sk.mid.exception.MidNotMidClientException;
import ee.sk.mid.exception.MidPhoneNotAvailableException;
import ee.sk.mid.exception.MidSessionTimeoutException;
import ee.sk.mid.exception.MidUserCancellationException;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.client.mobileid.MobileIdUserData;
import ee.cyber.cdoc2.exceptions.CdocMobileIdClientException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.ClientConfigurationUtil.getMobileIdConfiguration;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


class MobileIdClientTest {

    // OK for "TEST of SK ID Solutions EID-Q 2021E" certificate
    private static final String OK_1_IDENTITY_CODE = "51307149560";
    private static final String OK_1_PHONE_NUMBER = "+37269930366";

    // OK for "TEST of EID-SK 2016" certificate
    private static final String OK_2_IDENTITY_CODE = "60001017869";
    private static final String OK_2_PHONE_NUMBER = "+37268000769";

    private final MobileIdClient mobileIdClient;

    MobileIdClientTest() throws ConfigurationLoadingException {
        this.mobileIdClient = new MobileIdClient(getMobileIdConfiguration());
    }

    @Test
    void successfullyAuthenticateUser1() throws Exception {
        MobileIdUserData requestData = new MobileIdUserData(OK_1_PHONE_NUMBER, OK_1_IDENTITY_CODE);

        MidAuthenticationIdentity result = authenticate(requestData);

        assertNotNull(result);
        assertEquals(OK_1_IDENTITY_CODE, result.getIdentityCode());
    }

    @Test
    void successfullyAuthenticateUser2() throws Exception {
        MobileIdUserData requestData = new MobileIdUserData(OK_2_PHONE_NUMBER, OK_2_IDENTITY_CODE);

        MidAuthenticationIdentity result = authenticate(requestData);

        assertNotNull(result);
        assertEquals(OK_2_IDENTITY_CODE, result.getIdentityCode());
    }

    @Test
    void failAuthenticationWithInvalidPhoneNrFormat() {
        String invalidPhoneNrFormat = OK_1_PHONE_NUMBER.substring(1);
        assertThrows(
            IllegalArgumentException.class,
            () -> new MobileIdUserData(invalidPhoneNrFormat, OK_1_IDENTITY_CODE)
        );
    }

    @Test
    void failAuthenticationWithInvalidIdentityNumber() {
        String invalidIdNumber = OK_1_IDENTITY_CODE + "1";
        assertThrows(
            IllegalArgumentException.class,
            () -> new MobileIdUserData(OK_1_PHONE_NUMBER, invalidIdNumber)
        );
    }

    @Test
    void failAuthenticationOfNonExistingUser() {
        MobileIdUserData requestData = new MobileIdUserData("+37200000266", "60001019939");

        CdocMobileIdClientException exception = assertAuthenticationFails(requestData);

        assertTrue(exception.getCause().getMessage()
            .contains("User has no active certificates, and thus is not Mobile-ID client"));
        assertEquals(MidNotMidClientException.class, exception.getCause().getClass());
    }

    @Test
    void failAuthenticationWhenUserCancels() {
        MobileIdUserData requestData = new MobileIdUserData("+37201100266", "60001019950");

        CdocMobileIdClientException exception = assertAuthenticationFails(requestData);
        assertEquals(MidUserCancellationException.class, exception.getCause().getClass());
    }

    @Test
    void failAuthenticationWithSignatureHashMismatch() {
        MobileIdUserData requestData = new MobileIdUserData("+37200000666", "60001019961");

        CdocMobileIdClientException exception = assertAuthenticationFails(requestData);
        assertEquals(MidInvalidUserConfigurationException.class, exception.getCause().getClass());
    }

    @Test
    void failAuthenticationWithPhoneIsNotInCoverageArea() {
        MobileIdUserData requestData = new MobileIdUserData("+37213100266", "60001019983");

        CdocMobileIdClientException exception = assertAuthenticationFails(requestData);
        assertEquals(MidPhoneNotAvailableException.class, exception.getCause().getClass());
    }

    @Test
    void failAuthenticationWithSimError() {
        MobileIdUserData requestData = new MobileIdUserData("+37201200266", "60001019972");

        CdocMobileIdClientException exception = assertAuthenticationFails(requestData);
        assertEquals(MidDeliveryException.class, exception.getCause().getClass());
    }

    @Test
    void failAuthenticationWithTimeout() {
        MobileIdUserData requestData = new MobileIdUserData("+37266000266", "50001018908");

        CdocMobileIdClientException exception = assertAuthenticationFails(requestData);
        assertEquals(MidSessionTimeoutException.class, exception.getCause().getClass());
    }

    private MidAuthenticationIdentity authenticate(MobileIdUserData requestData)
        throws CdocMobileIdClientException {

        MidAuthenticationHashToSign authenticationHash
            = MidAuthenticationHashToSign.generateRandomHashOfDefaultType();
        return mobileIdClient.startAuthentication(requestData, authenticationHash);
    }

    private CdocMobileIdClientException assertAuthenticationFails(MobileIdUserData requestData) {
        return assertThrows(
            CdocMobileIdClientException.class,
            () -> authenticate(requestData)
        );
    }

}
