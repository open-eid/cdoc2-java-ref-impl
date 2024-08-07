package ee.cyber.cdoc2;

import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.util.SkLdapUtil;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.NamingException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;


class SkLdapTest {
    private static final Logger log = LoggerFactory.getLogger(SkLdapTest.class);

    // Igor cert is not available from SKs
    //private static final String id = "37101010021";//Igor

    @Test
    @Tag("ldap")
    void testFindAuthenticationCerts() throws NamingException, CertificateException {
        String[] ids = new String[]{"37903130370", "38207162766"};
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
