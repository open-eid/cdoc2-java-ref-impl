package ee.cyber.cdoc2.server.conf;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import java.io.File;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import ee.cyber.cdoc2.server.datagen.KeyStoreUtil;

/**
 * Gatling test configuration properties
 */
@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
@ToString
public class TestConfig {

    private final String getServerBaseUrl;
    private final String putServerBaseUrl;
    @ToString.Exclude
    private final List<LoadedKeyStore> eccKeyStores;
    @ToString.Exclude
    private final List<LoadedKeyStore> rsaKeyStores;
    private final Optional<LoadTestConfig> loadTestConfig;

    /**
     * Loads the configuration from file
     *
     * @param isLoadTest boolean indicating whether to read load test configuration
     *
     * see @link https://github.com/lightbend/config#standard-behavior for file names and formats
     */
    public static TestConfig load(boolean isLoadTest) {
        var conf = ConfigFactory.load();

        var keyStores = readClientKeyStores(conf);

        var testConf = new TestConfig(
            conf.getString("get-server.base-url"),
            conf.getString("put-server.base-url"),
            keyStores.stream().filter(x -> x.publicKey() instanceof ECPublicKey).toList(),
            keyStores.stream().filter(x -> x.publicKey() instanceof RSAPublicKey).toList(),
            isLoadTest ? Optional.of(readLoadTestConfig(conf)) : Optional.empty()
        );

        if (testConf.getEccKeyStores().size() < 2) {
            throw new IllegalArgumentException("Not enough elliptic curve key stores configured");
        }
        if (testConf.getRsaKeyStores().size() < 2) {
            throw new IllegalArgumentException("Not enough RSA key stores configured");
        }

        log.info("Loaded test configuration: {}", testConf);

        return testConf;
    }

    private static List<LoadedKeyStore> readClientKeyStores(Config config) {
        var clientKeyStoresConf = config.getConfig("client-keystores");

        File keystoreDir = new File(clientKeyStoresConf.getString("path"));
        String keystorePassword = clientKeyStoresConf.getString("password");
        String keyAlias = clientKeyStoresConf.getString("alias");

        if (!keystoreDir.exists() || !keystoreDir.isAbsolute()) {
            throw new IllegalArgumentException(
                "Invalid client keystore folder (must be absolute): " + keystoreDir
            );
        }

        var files = keystoreDir.listFiles();
        if (files == null) {
            throw new IllegalArgumentException(
                "Client keystore folder " + keystoreDir + " contains no files"
            );
        }

        var keyStores = new ArrayList<LoadedKeyStore>();
        Stream.of(files)
            .filter(file -> !file.isDirectory())
            .forEach(file -> {
                try {
                    var ks = KeyStoreUtil.loadKeyStore(file.toPath(), KeyStoreUtil.KEY_STORE_TYPE, keystorePassword);
                    var cert = KeyStoreUtil.getCertificate(ks, keystorePassword, keyAlias);
                    keyStores.add(
                        new LoadedKeyStore(
                            cert.getPublicKey(),
                            file,
                            KeyStoreUtil.KEY_STORE_TYPE,
                            keystorePassword
                        )
                    );
                } catch (Exception e) {
                    log.error("Failed to load keystore {}", file, e);
                }
            });
        log.info("Found {} key stores", keyStores.size());
        return keyStores;
    }

    private static LoadTestConfig readLoadTestConfig(Config config) {
        var create = config.getConfig("load-test.create-capsule");
        var get = config.getConfig("load-test.get-capsule");

        return new LoadTestConfig(
            new LoadTestParameters(
                create.getLong("increment-users-per-second"),
                create.getInt("increment-cycles"),
                create.getLong("cycle-duration-seconds"),
                create.getLong("start-users-per-second")
            ),
            new LoadTestParameters(
                get.getLong("increment-users-per-second"),
                get.getInt("increment-cycles"),
                get.getLong("cycle-duration-seconds"),
                get.getLong("start-users-per-second")
            ),
            get.getLong("initial-delay-seconds")
        );
    }
}
