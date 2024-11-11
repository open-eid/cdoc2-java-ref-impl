package ee.cyber.cdoc2;

import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.util.SkLdapUtil;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.NamingException;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;


class SkLdapTest {
    private static final Logger log = LoggerFactory.getLogger(SkLdapTest.class);

    @Test
    @Tag("ldap")
    void shouldFailToFindMissingAuthenticationCert() {
        // JAAK-KRISTJAN JÕEORG 38001085718 cert is not available from SK Ldap as he is a test
        // person and SK doesn't have test LDAP environment.
        String[] ids = new String[]{"38001085718"};
        assertThrows(CertificateException.class, () -> SkLdapUtil.getPublicKeysWithLabels(ids));
    }

    @Test
    @Tag("ldap")
    @Tag("net")
    @Disabled("Requires real ID code. As 38001085718 code is for test person - its certificate"
        + " is not available from SK LDAP. Needs to be run separately from other LDAP tests"
        + " with own ID code")
    void testFindAuthenticationCerts() throws NamingException, CertificateException {
        String[] ids = new String[]{"38001085718"}; // replace with own ID code for testing
        List<SkLdapUtil.CertificateData> keysWithLabels =  SkLdapUtil.getPublicKeysWithLabels(ids);

        // Since testing against external service, then can't be really sure what is returned
        // if something is returned then consider it success
        assertFalse(keysWithLabels.isEmpty());

        Map<PublicKey, String> ecKeysWithLabels = keysWithLabels.stream()
                .filter(entry -> EllipticCurve.isSupported(entry.getPublicKey()))
                .collect(Collectors.toMap(
                    SkLdapUtil.CertificateData::getPublicKey,
                    SkLdapUtil.CertificateData::getKeyLabel
                ));

        // all returned keys were supported by cdoc
        assertEquals(keysWithLabels.size(), ecKeysWithLabels.size());
    }

}
