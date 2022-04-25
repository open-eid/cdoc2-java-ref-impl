package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.EnvelopeTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.IOException;
import java.nio.file.Path;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Isolated
public class Pkcs11Test extends EnvelopeTest {
    private static final Logger log = LoggerFactory.getLogger(Pkcs11Test.class);

    // CN=ŽAIKOVSKI\,IGOR\,37101010021
    private char[] pin = {'3', '4', '7', '1'};
    //private List<String> expectedCn = List.of("ŽAIKOVSKI", "IGOR", "37101010021");
    private String id = "37101010021";

    @Test
    void testLoadKeyInteractively() throws GeneralSecurityException, IOException {
        KeyPair igorKeyPair = ECKeys.loadFromPKCS11Interactively(null, 0);
        assertTrue(Crypto.isPKCS11Key(igorKeyPair.getPrivate()));
        assertTrue(ECKeys.EllipticCurve.secp384r1.isValidKeyPair(igorKeyPair));
    }

    @Test
    void testLoadCert() throws IOException, GeneralSecurityException {
        Path sunpkcs11Conf = Crypto.createSunPkcsConfigurationFile(null, null, 0);
        AbstractMap.SimpleEntry<PrivateKey, X509Certificate> pair =
                ECKeys.loadFromPKCS11(sunpkcs11Conf, pin, null);

        X509Certificate cert = pair.getValue();


        List<String> cn;
        try {
            cn = new LdapName(cert.getSubjectX500Principal().getName()).getRdns().stream()
                            .filter(rdn-> rdn.getType().equalsIgnoreCase("cn"))
                            .map(rdn -> rdn.getValue().toString())
                    .toList();
        } catch (InvalidNameException e) {
            cn = List.of();
            log.error("InvalidNameException", e);
        }

        log.debug("CN {}", cn);

        //assertTrue(cn.contains(id));
    }

    @Test
    void testContainerUsingPKCS11Key(@TempDir Path tempDir) throws IOException, GeneralSecurityException, CDocParseException {
        log.trace("Pkcs11Test::testContainerUsingPKCS11Key");

        KeyPair igorKeyPair = ECKeys.loadFromPKCS11(null, 0, pin);

        log.debug("Using hardware private key for decrypting: {}", Crypto.isPKCS11Key(igorKeyPair.getPrivate()));
        assertTrue(Crypto.isPKCS11Key(igorKeyPair.getPrivate()));

        testContainer(tempDir, igorKeyPair);
    }
}
