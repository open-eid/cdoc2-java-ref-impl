package ee.cyber.cdoc2.mobileid;

import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.auth.SIDCertificateUtil;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.exception.MidDeliveryException;
import ee.sk.mid.exception.MidInvalidPhoneNumberException;
import ee.sk.mid.exception.MidInvalidUserConfigurationException;
import ee.sk.mid.exception.MidNotMidClientException;
import ee.sk.mid.exception.MidPhoneNotAvailableException;
import ee.sk.mid.exception.MidSessionTimeoutException;
import ee.sk.mid.exception.MidUserCancellationException;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.client.mobileid.MobileIdUserData;
import ee.cyber.cdoc2.exceptions.CdocMobileIdClientException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import static ee.cyber.cdoc2.ClientConfigurationUtil.getMobileIdConfiguration;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


class MobileIdClientTest {

    private final MobileIdClient mobileIdClient;

    MobileIdClientTest() throws ConfigurationLoadingException {
        this.mobileIdClient = new MobileIdClient(getMobileIdConfiguration());
    }

    @Test
    void shouldParseMobileIdCert() throws Exception {
        X509Certificate midCert = PemTools.loadCertificate(
            new ByteArrayInputStream(MIDTestData.OK_1_CERT_PEM.getBytes(StandardCharsets.UTF_8)));
        String semanticsIdentifier = SIDCertificateUtil.getSemanticsIdentifier(midCert);
        EtsiIdentifier etsiIdentifier = new EtsiIdentifier(EtsiIdentifier.PREFIX + semanticsIdentifier);

        assertEquals(MIDTestData.OK_1_IDENTITY_CODE, etsiIdentifier.getIdentifier());
    }


    @Tag("net")
    @Test
    void successfullyAuthenticateUser1() throws Exception {
        MobileIdUserData requestData = new MobileIdUserData(MIDTestData.OK_1_PHONE_NUMBER,
            MIDTestData.OK_1_IDENTITY_CODE);

        MidAuthentication result = authenticate(requestData);

        String semanticsIdentifier = SIDCertificateUtil.getSemanticsIdentifier(result.getCertificate());
        EtsiIdentifier etsiIdentifier = new EtsiIdentifier(EtsiIdentifier.PREFIX + semanticsIdentifier);


        assertNotNull(result);
        assertEquals(MIDTestData.OK_1_IDENTITY_CODE, etsiIdentifier.getIdentifier());
    }

    @Tag("net")
    @Test
    void successfullyAuthenticateUser2() throws Exception {
        MobileIdUserData requestData = new MobileIdUserData(MIDTestData.OK_2_PHONE_NUMBER,
            MIDTestData.OK_2_IDENTITY_CODE);

        MidAuthentication result = authenticate(requestData);

        String semanticsIdentifier = SIDCertificateUtil.getSemanticsIdentifier(result.getCertificate());
        EtsiIdentifier etsiIdentifier = new EtsiIdentifier(EtsiIdentifier.PREFIX + semanticsIdentifier);

        assertNotNull(result);
        assertEquals(MIDTestData.OK_2_IDENTITY_CODE, etsiIdentifier.getIdentifier());
    }


    @Tag("net")
    @Test
    void failAuthenticationWithInvalidPhoneNrFormat() {
        String invalidPhoneNrFormat = MIDTestData.OK_1_PHONE_NUMBER.substring(1);
        assertThrows(
            MidInvalidPhoneNumberException.class,
            () -> new MobileIdUserData(invalidPhoneNrFormat, MIDTestData.OK_1_IDENTITY_CODE)
        );
    }

    @Tag("net")
    @Test
    void failAuthenticationWithInvalidIdentityNumber() {
        String invalidIdNumber = MIDTestData.OK_1_IDENTITY_CODE + "1";
        assertThrows(
            IllegalArgumentException.class,
            () -> new MobileIdUserData(MIDTestData.OK_1_PHONE_NUMBER, invalidIdNumber)
        );
    }

    @Tag("net")
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

    private MidAuthentication authenticate(MobileIdUserData requestData)
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
