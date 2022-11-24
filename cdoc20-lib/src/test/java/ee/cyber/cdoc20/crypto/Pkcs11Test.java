package ee.cyber.cdoc20.crypto;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.List;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc20.container.EnvelopeTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

// Tests here will fail without correct id-kaart
@Isolated
public class Pkcs11Test extends EnvelopeTest {
    private static final Logger log = LoggerFactory.getLogger(Pkcs11Test.class);

    // card specific data, checked from tests
    // CN=ŽAIKOVSKI\,IGOR\,37101010021
    private final char[] pin = {'3', '4', '7', '1'};
    private final String id = "37101010021";

    @Test
    @Tag("pkcs11")
    void testLoadKeyInteractively() throws GeneralSecurityException, IOException {
        // seems that when pin has already been provided to SunPKCS11, then pin is not asked again
        // so running this test with other tests doesn't make much sense
        KeyPair igorKeyPair = ECKeys.loadFromPKCS11Interactively(null, 0);
        assertTrue(Crypto.isECPKCS11Key(igorKeyPair.getPrivate()));
        assertTrue(ECKeys.EllipticCurve.secp384r1.isValidKeyPair(igorKeyPair));
    }

    @Test
    @Tag("pkcs11")
    void testLoadCert() throws IOException, GeneralSecurityException {
        Path sunpkcs11Conf = Crypto.createSunPkcsConfigurationFile(null, null, 0);
        AbstractMap.SimpleEntry<PrivateKey, X509Certificate> pair =
                ECKeys.loadFromPKCS11(sunpkcs11Conf, pin, null);

        X509Certificate cert = pair.getValue();

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
    @Tag("pkcs11")
    void testContainerUsingPKCS11Key(@TempDir Path tempDir) throws Exception {

        log.trace("Pkcs11Test::testContainerUsingPKCS11Key");
        KeyPair igorKeyPair = ECKeys.loadFromPKCS11(null, 0, pin);

        log.debug("Using hardware private key for decrypting: {}", Crypto.isECPKCS11Key(igorKeyPair.getPrivate()));
        assertTrue(Crypto.isECPKCS11Key(igorKeyPair.getPrivate()));

        testContainer(tempDir, igorKeyPair, "testContainerUsingPKCS11Key", null);
    }


    // override EnvelopeTest tests so that they are not executed twice
    void testLongHeader(@TempDir Path tempDir) {
    }

    void testContainerWrongPoly1305Mac(@TempDir Path tempDir) throws IOException, GeneralSecurityException {
    }

    void testContainer(@TempDir Path tempDir) {
    }

    void testHeaderSerializationParse() {
    }

// DSS and cdoc4j style SunPKCS11 initialization through reflection fails on OpenJDK 17.0.2 with IllegalAccessException
//    private Provider getProviderJavaGreaterOrEquals9(String configString)
//      throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {
//            Provider provider = Security.getProvider("SunPKCS11");
//            Method configureMethod = provider.getClass().getMethod("configure", String.class);
//            // "--" is permitted in the constructor sun.security.pkcs11.Config
//            return (Provider) configureMethod.invoke(provider, "--" + configString);
//    }
//
//    @Test
//    void testGetProviderJavaGreaterOrEquals9()
//    throws IOException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
//        Path confPath = Crypto.createSunPkcsConfigurationFile(null, null, null);
//        String conf = Files.readString(confPath, StandardCharsets.UTF_8);
//        Provider sunpkcs11 = getProviderJavaGreaterOrEquals9(conf);
//    }
}
