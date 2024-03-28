package ee.cyber.cdoc2.server.datagen;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;
import javax.security.auth.x500.X500Principal;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility class for dealing with key stores
 */
@Slf4j
public final class KeyStoreUtil {
    // the type of generated key store
    public static final String KEY_STORE_TYPE = "pkcs12";

    private KeyStoreUtil() {
        // utility class
    }

    /**
     * Generates a new key store, signs the certificate using the root certificate
     * @param fullPath the absolute path of the file to write the keystore to
     * @param alias the alias
     * @param password the keystore password
     * @param cn the CN for the certificate
     * @param caKeyPair the CA keypair to use to sign the certificate
     * @param caCert the CA certificate
     * @param keyPairGenerator the key pair generator
     */
    @SneakyThrows
    public static void generateKeyStore(Path fullPath, String alias, String password, String cn,
            KeyPair caKeyPair, X509Certificate caCert, Supplier<KeyPair> keyPairGenerator) {
        KeyStore ks = KeyStore.getInstance(KEY_STORE_TYPE);
        // no password
        ks.load(null, null);

        try (var out = new FileOutputStream(fullPath.toAbsolutePath().toString())) {
            X500Principal subject = new X500Principal("CN=" + cn);
            X500Principal signer = caCert.getIssuerX500Principal();

            var clientKeys = keyPairGenerator.get();
            var clientCert = CertUtil.generateCertificate(
                subject, clientKeys, signer, caKeyPair, cn
            );

            X509Certificate[] chain = new X509Certificate[2];
            chain[0] = clientCert;
            chain[1] = caCert;

            ks.setKeyEntry(alias, clientKeys.getPrivate(), password.toCharArray(), chain);
            ks.store(out, password.toCharArray());
        }
    }

    @SneakyThrows
    public static KeyStore loadKeyStore(Path file, String type, String password) {
        KeyStore ks = KeyStore.getInstance(type);
        ks.load(new FileInputStream(file.toAbsolutePath().toString()), password.toCharArray());
        log.info("Loaded keystore {} with {} entries", file, ks.size());
        return ks;
    }

    @SneakyThrows
    public static Certificate getCertificate(KeyStore keyStore, String password, String alias) {
        var key = keyStore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            return keyStore.getCertificate(alias);
        } else {
            throw new IllegalArgumentException(
                "Unsupported keystore, expecting private key, got " + key.getClass()
            );
        }
    }
}
