package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.container.EnvelopeTest;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static ee.cyber.cdoc20.crypto.Pkcs11Tools.createSunPkcsConfigurationFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * These tests will fail without a PKCS11 device (smart card, usb token).
 * The device and its details can be configured using a properties file under src/test/resources/
 * @see Pkcs11DeviceConfiguration for details
 */
@Isolated
public class Pkcs11Test {
    private static final Logger log = LoggerFactory.getLogger(Pkcs11Test.class);

    // load pkcs11 devive properties
    private static final Pkcs11DeviceConfiguration CONF = Pkcs11DeviceConfiguration.load();

    @Test
    @Tag("pkcs11")
    void testLoadKeyInteractively() throws Exception {
        // seems that when pin has already been provided to SunPKCS11, then pin is not asked again
        // so running this test with other tests doesn't make much sense
        KeyPair keyPair = Pkcs11Tools.loadFromPKCS11Interactively(
            CONF.pkcs11Library(), CONF.slot(), CONF.keyAlias()
        );

        if (Crypto.isECPKCS11Key(keyPair.getPrivate())) {
            assertTrue(EllipticCurve.secp384r1.isValidKeyPair(keyPair));
        }
    }

    @Test
    @Tag("pkcs11")
    void testLoadCert() throws Exception {
        var pair = Pkcs11Tools.loadFromPKCS11(
            createSunPkcsConfigurationFile(null, CONF.pkcs11Library(), CONF.slot()),
            new KeyStore.PasswordProtection(CONF.pin()),
            CONF.keyAlias()
        );

        X509Certificate cert = pair.getValue();

        List<String> cn;
        try {
            cn = new LdapName(cert.getSubjectX500Principal().getName())
                .getRdns().stream()
                .filter(rdn -> rdn.getType().equalsIgnoreCase("cn"))
                .map(rdn -> rdn.getValue().toString())
                .toList();
        } catch (InvalidNameException e) {
            cn = List.of();
            log.error("InvalidNameException", e);
        }

        log.debug("CN {}", cn);

        assertEquals(1, cn.size());
        assertTrue(cn.get(0).contains(CONF.certCn()));
    }

    @Test
    @Tag("pkcs11")
    void testContainerUsingPKCS11Key(@TempDir Path tempDir) throws Exception {

        log.trace("Pkcs11Test::testContainerUsingPKCS11Key");
        KeyPair keyPair = loadFromPKCS11();

        log.debug("Using hardware private key for decrypting");

        EnvelopeTest.testContainer(tempDir, keyPair, "testContainerUsingPKCS11Key", null);
    }

    private static KeyPair loadFromPKCS11() throws Exception {
        Path confPath = createSunPkcsConfigurationFile("OpenSC", CONF.pkcs11Library(), CONF.slot());
        var entry = Pkcs11Tools.loadFromPKCS11(
            confPath, new KeyStore.PasswordProtection(CONF.pin()), CONF.keyAlias()
        );
        return new KeyPair(entry.getValue().getPublicKey(), entry.getKey());
    }
}
