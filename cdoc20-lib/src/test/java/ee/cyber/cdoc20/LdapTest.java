package ee.cyber.cdoc20;

import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.util.LdapUtil;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import javax.naming.NamingException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LdapTest {
    private static final Logger log = LoggerFactory.getLogger(LdapTest.class);

    // Igor cert is not available from SKs
    //private static final String id = "37101010021";//Igor
    private static final String id = "37903130370";


    @Test
    @Tag("ldap")
    void testFindAuthenticationCerts() throws NamingException, CertificateException {
        List<PublicKey> keys =  LdapUtil.getCertKeys(new String[]{id, "38207162766"});

        // Since testing against external service, then can't be really sure what is returned
        // if something is returned then consider it success
        assertTrue(!keys.isEmpty());

        List<ECPublicKey> ecPublicKeys = keys.stream()
                .filter(ECKeys.EllipticCurve::isSupported)
                .map(publicKey -> (ECPublicKey)publicKey)
                .toList();

        // all returned keys were supported by cdoc
        assertEquals(keys.size(), ecPublicKeys.size());
    }

}
