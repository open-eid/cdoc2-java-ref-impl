package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.server.conf.TestConfig;
import ee.cyber.cdoc20.server.scenarios.EccKeyCapsuleScenarios;
import ee.cyber.cdoc20.server.scenarios.RsaKeyCapsuleScenarios;
import io.gatling.commons.shared.unstable.util.Ssl;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import javax.net.ssl.KeyManagerFactory;
import lombok.extern.slf4j.Slf4j;
import scala.Option;
import scala.Some;
import static io.gatling.javaapi.core.CoreDsl.global;
import static io.gatling.javaapi.core.CoreDsl.incrementUsersPerSec;
import static io.gatling.javaapi.core.CoreDsl.nothingFor;
import static io.gatling.javaapi.core.CoreDsl.scenario;
import static io.gatling.javaapi.http.HttpDsl.http;

/**
 * Load tests for the key-capsules API
 */
@Slf4j
public final class KeyCapsuleLoadTests extends Simulation {

    private final TestConfig config = TestConfig.load(true);
    private final TestDataGenerator testData = new TestDataGenerator(this.config);
    private final EccKeyCapsuleScenarios eccScenarios = new EccKeyCapsuleScenarios(this.config, this.testData);
    private final RsaKeyCapsuleScenarios rsaScenarios = new RsaKeyCapsuleScenarios(this.config, this.testData);

    HttpProtocolBuilder httpConf = http
        .baseUrl(this.config.getGetServerBaseUrl())
        .acceptHeader("application/json")
        .perUserKeyManagerFactory(this::getKeyManager)
        .disableWarmUp();

    {
        var loadTestConfig = this.config.getLoadTestConfig()
            .orElseThrow(() -> new IllegalArgumentException("No load test configuration"));

        var createConf = loadTestConfig.getCreateCapsule();
        var getConf = loadTestConfig.getGetCapsule();

        // divide conf values by 2 to get equal amount of ec and rsa scenarios executed
        var createScnIncUsersPerSec = createConf.getIncrementUsersPerSec() / 2.0;
        var createScnStartUsersPerSec = createConf.getStartingUsersPerSec() / 2.0;
        var getScnIncUsersPerSec = getConf.getIncrementUsersPerSec() / 2.0;
        var getScnStartUsersPerSec = getConf.getStartingUsersPerSec() / 2.0;

        setUp(
            scenario("Send ecc key capsule")
                .exec(this.eccScenarios.sendEccKeyCapsule())
                .injectOpen(
                    incrementUsersPerSec(createScnIncUsersPerSec)
                        .times(createConf.getIncrementCycles())
                        .eachLevelLasting(createConf.getCycleDurationSec())
                        .startingFrom(createScnStartUsersPerSec)
                ),
            scenario("Send rsa key capsule")
                .exec(this.rsaScenarios.sendRsaKeyCapsule())
                .injectOpen(
                    incrementUsersPerSec(createScnIncUsersPerSec)
                        .times(createConf.getIncrementCycles())
                        .eachLevelLasting(createConf.getCycleDurationSec())
                        .startingFrom(createScnStartUsersPerSec)
                ),
            this.eccScenarios.getRandomKeyCapsule("Get random ecc key capsule")
                .injectOpen(
                    // wait for some capsules to be created and their urls returned
                    nothingFor(loadTestConfig.getGetCapsuleStartDelay()),
                    incrementUsersPerSec(getScnIncUsersPerSec)
                        .times(getConf.getIncrementCycles())
                        .eachLevelLasting(getConf.getCycleDurationSec())
                        .startingFrom(getScnStartUsersPerSec)
                ),
            this.rsaScenarios.getRandomKeyCapsule("Get random rsa key capsule")
                .injectOpen(
                    // wait for some capsules to be created and their urls returned
                    nothingFor(loadTestConfig.getGetCapsuleStartDelay()),
                    incrementUsersPerSec(getScnIncUsersPerSec)
                        .times(getConf.getIncrementCycles())
                        .eachLevelLasting(getConf.getCycleDurationSec())
                        .startingFrom(getScnStartUsersPerSec)
                )
        )
        .protocols(this.httpConf)
        .assertions(global().successfulRequests().percent().is(100.0));
    }

    // returns the key store to use for the user injected by Gatling
    private KeyManagerFactory getKeyManager(long userId) {
        var keyStore = this.testData.getEccKeyStore(userId);
        return Ssl.newKeyManagerFactory(
            new Some<>(keyStore.keyStoreType()),
            keyStore.file().getAbsolutePath(),
            keyStore.password(),
            Option.empty()
        );
    }
}
