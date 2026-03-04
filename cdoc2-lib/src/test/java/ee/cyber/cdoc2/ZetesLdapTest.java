package ee.cyber.cdoc2;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.util.SkLdapUtil;
import ee.cyber.cdoc2.util.ZetesLdapUtil;

import static org.junit.jupiter.api.Assertions.*;

class ZetesLdapTest {

    @Test
    @Tag("ldap")
    void shouldFailToFindMissingAuthenticationCert() {
        // Non existent ID code
        String[] ids = new String[]{"30000000000"};
        assertThrows(NameNotFoundException.class, () -> ZetesLdapUtil.getPublicKeysWithLabels(ids));
    }

    @Test
    @Tag("ldap")
    @Tag("net")
    void testFindAuthenticationCertsFromTestServer() throws NamingException, CertificateException {
        String[] ids = new String[]{"38001085718"};
        List<ZetesLdapUtil.CertificateData> keysWithLabels =
            ZetesLdapUtil.getPublicKeysWithLabelsFromTestServer(ids);

        // Since testing against external service, then can't be really sure what is returned
        // if something is returned then consider it success
        assertFalse(keysWithLabels.isEmpty());

        Map<PublicKey, String> ecKeysWithLabels = keysWithLabels.stream()
            .filter(entry -> EllipticCurve.isSupported(entry.getPublicKey()))
            .collect(Collectors.toMap(
                ZetesLdapUtil.CertificateData::getPublicKey,
                ZetesLdapUtil.CertificateData::getKeyLabel
            ));

        // all returned keys were supported by cdoc
        assertEquals(keysWithLabels.size(), ecKeysWithLabels.size());
    }

    @Test
    @Tag("ldap")
    @Tag("net")
    @Disabled("Requires real ID code. As 38001085718 code is for test person - its certificate"
        + " is not available from live Zetes LDAP. Needs to be run separately from other LDAP tests"
        + " with own ID code (if you have Thales ID card)")
    void testFindAuthenticationCerts() throws NamingException, CertificateException {
        String[] ids = new String[]{"38001085718"}; // replace with own ID code for testing
        List<SkLdapUtil.CertificateData> keysWithLabels =  ZetesLdapUtil.getPublicKeysWithLabels(ids);

        // Since testing against external service, then can't be really sure what is returned
        // if something is returned then consider it success
        assertFalse(keysWithLabels.isEmpty());

        Map<PublicKey, String> ecKeysWithLabels = keysWithLabels.stream()
            .filter(entry -> EllipticCurve.isSupported(entry.getPublicKey()))
            .collect(Collectors.toMap(
                ZetesLdapUtil.CertificateData::getPublicKey,
                ZetesLdapUtil.CertificateData::getKeyLabel
            ));

        // all returned keys were supported by cdoc
        assertEquals(keysWithLabels.size(), ecKeysWithLabels.size());
    }
}
