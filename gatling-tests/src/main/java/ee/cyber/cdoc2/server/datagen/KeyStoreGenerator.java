package ee.cyber.cdoc2.server.datagen;

import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

/**
 * Java key store generator for test input data
 */
@Slf4j
public final class KeyStoreGenerator {

    private KeyStoreGenerator() {
        // utility class
    }

    @SneakyThrows
    public static void main(String[] args) {
        String outputDir = getRequiredProperty("output-dir");
        String keystorePassword = getRequiredProperty("keystore-password");
        String keyAlias = getRequiredProperty("key-alias");
        int amount = Integer.parseInt(getRequiredProperty("amount"));

        String rootKeyStorePath = getRequiredProperty("root-keystore");
        String rootKeyStoreType = System.getProperty("root-keystore-type", "pkcs12");
        String rootKeyStorePassword = getRequiredProperty("root-keystore-password");
        String rootKeyAlias = getRequiredProperty("root-key-alias");

        log.info("Output folder: {}", outputDir);
        log.info("KeyStores to generate: {}", amount);
        log.info("Root keystore: {}", rootKeyStorePath);
        log.info("Root keystore type: {}", rootKeyStoreType);

        KeyStore rootKeyStore = KeyStoreUtil.loadKeyStore(
            Paths.get(rootKeyStorePath), rootKeyStoreType, rootKeyStorePassword
        );
        X509Certificate rootCert = (X509Certificate) rootKeyStore.getCertificate(rootKeyAlias);
        var rootKeyPair = new KeyPair(
            rootCert.getPublicKey(),
            (PrivateKey) rootKeyStore.getKey(rootKeyAlias, rootKeyStorePassword.toCharArray())
        );

        for (int i = 0; i < amount; i++) {
            var fileName = Paths.get(outputDir, String.format("ks-%d.p12", i + 1));
            KeyStoreUtil.generateKeyStore(
                fileName,
                keyAlias,
                keystorePassword,
                "localhost",
                rootKeyPair,
                rootCert,
                i % 2 == 0 ? CertUtil::generateEcKeyPair : CertUtil::generateRsaKeyPair
            );
        }
    }

    private static String getRequiredProperty(String property) {
        return Optional.ofNullable(System.getProperty(property))
            .orElseThrow(() -> new IllegalArgumentException(
                "Required property '" + property + "' not set."
            ));
    }
}
