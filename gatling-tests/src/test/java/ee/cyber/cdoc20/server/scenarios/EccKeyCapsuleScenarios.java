package ee.cyber.cdoc20.server.scenarios;

import io.gatling.commons.shared.unstable.util.Ssl;
import io.gatling.javaapi.core.ChainBuilder;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.netty.handler.codec.http.HttpResponseStatus;
import lombok.extern.slf4j.Slf4j;
import scala.Option;
import scala.Some;

import javax.net.ssl.KeyManagerFactory;

import ee.cyber.cdoc20.server.TestDataGenerator;
import ee.cyber.cdoc20.server.conf.TestConfig;

import static ee.cyber.cdoc20.server.scenarios.ScenarioIdentifiers.*;
import static io.gatling.javaapi.core.CoreDsl.scenario;

/**
 * Test scenarios for elliptic curve key capsules
 */
@Slf4j
@SuppressWarnings("unchecked") // compiler warning come from usage of Gatling API
public class EccKeyCapsuleScenarios extends KeyCapsuleScenarios {

    public EccKeyCapsuleScenarios(TestConfig conf, TestDataGenerator generator) {
        super(conf, generator);
    }

    // returns the key store to use for the user injected by Gatling
    public KeyManagerFactory getKeyManager(long userId) {
        var keyStore = this.testData.getEccKeyStore(userId);
        return Ssl.newKeyManagerFactory(
            new Some<>(keyStore.keyStoreType()),
            keyStore.file().getAbsolutePath(),
            keyStore.password(),
            Option.empty()
        );
    }

    public ScenarioBuilder sendAndGetEccKeyCapsule() {
        return scenario("Send and get ecc capsule")
            .exec(this.sendEccKeyCapsule())
            .exec(this.getAndCheckEccKeyCapsule());
    }

    public ScenarioBuilder getRecipientMismatch() {
        return scenario("Request EC capsule with mismatching recipient")
            .exec(this.sendKeyCapsuleCheckSuccess(
                this.testData::generateEccCapsuleWithWrongRecipient, NEG_GET_06 + " create")
            )
            .exec(this.checkKeyCapsuleMismatch(NEG_GET_06 + " get"));
    }

    public ScenarioBuilder getWithInvalidTransactionIds() {
        return scenario("Request capsule with invalid transactionId values")
            .exec(
                this.checkInvalidTransactionId(
                    NEG_GET_02, TestDataGenerator.randomString(TX_ID_MIN_LENGTH),
                    HttpResponseStatus.NOT_FOUND
                ),
                this.checkInvalidTransactionId(NEG_GET_03, "123", HttpResponseStatus.BAD_REQUEST),
                this.checkInvalidTransactionId(NEG_GET_04, "", HttpResponseStatus.METHOD_NOT_ALLOWED),
                this.checkInvalidTransactionId(
                    NEG_GET_05, TestDataGenerator.randomString(TX_ID_MAX_LENGTH + 1),
                    HttpResponseStatus.BAD_REQUEST
                )
            )
            .exitHereIfFailed();
    }

    public ScenarioBuilder sendEccKeyCapsule() {
        return scenario("Send ecc capsule").exec(
            this.sendKeyCapsuleCheckSuccess(this.testData::generateEccCapsule, POS_PUT_01 + " - Create ecc key capsule")
        );
    }

    public ScenarioBuilder sendEccKeyCapsuleRepeatedly() {
        var capsule = this.testData.generateEccCapsule(1L);

        return scenario("Send same ecc capsule twice").exec(
            this.sendKeyCapsuleCheckSuccess(x -> capsule, POS_PUT_03 + " - 1st"),
            this.sendKeyCapsuleCheckSuccess(x -> capsule, POS_PUT_03 + " - 2nd")
        );
    }

    private ChainBuilder getAndCheckEccKeyCapsule() {
        return this.checkLatestKeyCapsule(POS_GET_02 + " - Get correct ecc key capsule");
    }
}
