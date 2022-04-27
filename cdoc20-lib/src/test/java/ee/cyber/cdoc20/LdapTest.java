package ee.cyber.cdoc20;

import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.util.LdapUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LdapTest {
    private static final Logger log = LoggerFactory.getLogger(LdapTest.class);

    // Igor cert is not available from SKs
    //private static final String id = "37101010021";//Igor
    private static final String id = "37903130370";

    @Test
    void testFindCert() throws NamingException, CertificateException {

        X509Certificate cert = LdapUtil.findEstEIDCertificate(id);
        assertNotNull(cert);

        List<String> cn;
        try {
            cn = new LdapName(cert.getSubjectX500Principal().getName()).getRdns().stream()
                    .filter(rdn -> rdn.getType().equalsIgnoreCase("cn"))
                    .map(rdn -> rdn.getValue().toString())
                    .toList();
        } catch (InvalidNameException e) {
            cn = List.of();
            log.error("InvalidNameException", e);
        }

        log.debug("CN {}", cn);

        assertTrue(cn.size() == 1);
        assertTrue(cn.get(0).contains(id));
    }

    @Test
    void testGetCertKeys() throws NamingException, GeneralSecurityException {
        List<ECPublicKey> keys =  LdapUtil.getCertKeys(new String[]{id});

        assertTrue(!keys.isEmpty());

        ECPublicKey ecPublicKey = keys.get(0);
        assertTrue(ECKeys.EllipticCurve.secp384r1.isValidKey(ecPublicKey));
    }

}
