package ee.cyber.cdoc2.smartid;

import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.SmartIdAuthenticationResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.exceptions.SmartIdClientException;

import static org.junit.jupiter.api.Assertions.*;


class SmartIdClientTest {

    private static final String CERT_LEVEL_ADVANCED = "ADVANCED";
    private static final String CERT_LEVEL_QUALIFIED = "QUALIFIED";
    private static final String IDENTITY_NUMBER = "30303039914";

    private final SmartIdClient smartIdClient;

    SmartIdClientTest() throws ConfigurationLoadingException {
        this.smartIdClient = new SmartIdClient();
    }

    @Test
    void successfullyAuthenticateUser() throws Exception {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
            // 3 character identity type
            // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
            SemanticsIdentifier.IdentityType.PNO,
            SemanticsIdentifier.CountryCode.EE,
            IDENTITY_NUMBER
        );

        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
        SmartIdAuthenticationResponse authResponse = smartIdClient.authenticate(
            IDENTITY_NUMBER,
            semanticsIdentifier,
            authenticationHash,
            CERT_LEVEL_QUALIFIED
        );

        assertNotNull(authResponse);
        assertEquals("OK", authResponse.getEndResult());
    }

    @Test
    void failAuthenticationOfNonExistingUser() {
        String nonExistingIdNumber = "12345678900";
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
            SemanticsIdentifier.IdentityType.PNO,
            SemanticsIdentifier.CountryCode.EE,
            nonExistingIdNumber
        );

        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
        SmartIdClientException exception = assertThrows(SmartIdClientException.class,
            () -> smartIdClient.authenticate(
                nonExistingIdNumber,
                semanticsIdentifier,
                authenticationHash,
                CERT_LEVEL_QUALIFIED
            )
        );

        assertTrue(exception.getMessage().contains("There is no such user account"));
    }

}
