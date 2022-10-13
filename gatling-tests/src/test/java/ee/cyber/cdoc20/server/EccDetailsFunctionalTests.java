package ee.cyber.cdoc20.server;

import io.gatling.commons.shared.unstable.util.Ssl;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import lombok.extern.slf4j.Slf4j;
import scala.Option;
import scala.Some;

import javax.net.ssl.KeyManagerFactory;

import ee.cyber.cdoc20.server.conf.TestConfig;

import static io.gatling.javaapi.core.CoreDsl.atOnceUsers;
import static io.gatling.javaapi.core.CoreDsl.global;
import static io.gatling.javaapi.http.HttpDsl.http;


/**
 * Functional tests for the ecc-details API endpoint
 */
@Slf4j
public final class EccDetailsFunctionalTests extends Simulation {

    private final TestConfig config = TestConfig.load(false);
    private final TestDataGenerator testData = new TestDataGenerator(this.config);
    private final EccDetailsScenarios scenarios = new EccDetailsScenarios(this.testData);

    HttpProtocolBuilder httpConf = http
        .baseUrl(this.config.getServerBaseUrl())
        .acceptHeader("application/json")
        .perUserKeyManagerFactory(this::getKeyManager)
        .disableWarmUp();

    {
        setUp(
            this.scenarios.createAndGetCreateEccDetails().injectOpen(atOnceUsers(1)),
            this.scenarios.createAndGetRecipientTransactionMismatch().injectOpen(atOnceUsers(1)),
            this.scenarios.getWithInvalidTransactionIds().injectOpen(atOnceUsers(1))
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
