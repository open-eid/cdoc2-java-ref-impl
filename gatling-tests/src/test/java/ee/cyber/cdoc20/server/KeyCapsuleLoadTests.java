package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.server.conf.TestConfig;
import io.gatling.commons.shared.unstable.util.Ssl;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import javax.net.ssl.KeyManagerFactory;
import lombok.extern.slf4j.Slf4j;
import scala.Option;
import scala.Some;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;

/**
 * Load tests for the key-capsules API
 */
@Slf4j
public final class KeyCapsuleLoadTests extends Simulation {

    private final TestConfig config = TestConfig.load(true);
    private final TestDataGenerator testData = new TestDataGenerator(this.config);
    private final EccKeyCapsuleScenarios scenarios = new EccKeyCapsuleScenarios(this.config, this.testData);

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

        setUp(
            this.scenarios.createEccKeyCapsule().injectOpen(
                incrementUsersPerSec(createConf.getIncrementUsersPerSec())
                    .times(createConf.getIncrementCycles())
                    .eachLevelLasting(createConf.getCycleDurationSec())
                    .startingFrom(createConf.getStartingUsersPerSec())
            ),
            this.scenarios.getRandomEccKeyCapsule().injectOpen(
                // wait for some capsules to be created and their urls returned
                nothingFor(loadTestConfig.getGetCapsuleStartDelay()),
                incrementUsersPerSec(getConf.getIncrementUsersPerSec())
                    .times(getConf.getIncrementCycles())
                    .eachLevelLasting(getConf.getCycleDurationSec())
                    .startingFrom(getConf.getStartingUsersPerSec())
            )
        )
        .protocols(this.httpConf)
        .assertions(global().successfulRequests().percent().is(100.0));
    }

    // returns the key store to use for the user injected by Gatling
    private KeyManagerFactory getKeyManager(long userId) {
        var keyStore = this.testData.getClientKeyStore(userId);
        return Ssl.newKeyManagerFactory(
            new Some<>(keyStore.getType()),
            keyStore.getFile().getAbsolutePath(),
            keyStore.getPassword(),
            Option.empty()
        );
    }
}
