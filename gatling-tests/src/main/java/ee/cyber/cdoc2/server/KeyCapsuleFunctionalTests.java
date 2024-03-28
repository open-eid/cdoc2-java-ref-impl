package ee.cyber.cdoc2.server;

import ee.cyber.cdoc2.server.conf.TestConfig;
import ee.cyber.cdoc2.server.scenarios.EccKeyCapsuleScenarios;
import ee.cyber.cdoc2.server.scenarios.RsaKeyCapsuleScenarios;

import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import lombok.extern.slf4j.Slf4j;
import static io.gatling.javaapi.core.CoreDsl.atOnceUsers;
import static io.gatling.javaapi.core.CoreDsl.global;
import static io.gatling.javaapi.http.HttpDsl.http;


/**
 * Functional tests for the key-capsules API
 */
@Slf4j
@SuppressWarnings("squid:S2187") //SonarQube: TestCases should contain tests
public final class KeyCapsuleFunctionalTests extends Simulation {

    private final TestConfig config = TestConfig.load(false);
    private final TestDataGenerator testData = new TestDataGenerator(this.config);
    private final EccKeyCapsuleScenarios eccScenarios = new EccKeyCapsuleScenarios(config, testData);
    private final RsaKeyCapsuleScenarios rsaScenarios = new RsaKeyCapsuleScenarios(config, testData);

    HttpProtocolBuilder eccClient = http
        .acceptHeader("application/json")
        .perUserKeyManagerFactory(this.eccScenarios::getKeyManager)
        .disableWarmUp();

    HttpProtocolBuilder rsaClient = http
        .acceptHeader("application/json")
        .perUserKeyManagerFactory(this.rsaScenarios::getKeyManager)
        .disableWarmUp();

    {
        setUp(
            // elliptic curve key capsule scenarios
           this.eccScenarios.sendAndGetEccKeyCapsule()
                .injectOpen(atOnceUsers(1))
                .protocols(this.eccClient),
            this.eccScenarios.sendEccKeyCapsuleRepeatedly()
                .injectOpen(atOnceUsers(1))
                .protocols(this.eccClient),
            this.eccScenarios.getRecipientMismatch()
                .injectOpen(atOnceUsers(1))
                .protocols(this.eccClient),
            this.eccScenarios.getWithInvalidTransactionIds()
                .injectOpen(atOnceUsers(1))
                .protocols(this.eccClient),

            this.rsaScenarios.sendRsaKeyCapsuleRandomKeyMaterial()
                .injectOpen(atOnceUsers(1))
                .protocols(this.eccClient),

            // rsa key capsule scenarios
            this.rsaScenarios.sendAndGetRsaKeyCapsule()
                .injectOpen(atOnceUsers(1))
                .protocols(this.rsaClient),
            this.rsaScenarios.sendRsaKeyCapsuleRepeatedly()
                .injectOpen(atOnceUsers(1))
                .protocols(this.rsaClient),
            this.rsaScenarios.sendAndGetRecipientMismatch()
                .injectOpen(atOnceUsers(1))
                .protocols(this.rsaClient),
            this.rsaScenarios.sendRsaKeyCapsuleTooBigKeyMaterial()
                .injectOpen(atOnceUsers(1))
                .protocols(this.rsaClient)
        )
        .assertions(global().successfulRequests().percent().is(100.0));
    }
}
