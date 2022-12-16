package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.server.conf.TestConfig;
import ee.cyber.cdoc20.server.dto.GeneratedCapsule;
import io.gatling.javaapi.core.ChainBuilder;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.netty.handler.codec.http.HttpResponseStatus;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_GET_02;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_GET_03;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_GET_04;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_GET_05;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_GET_06;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.POS_PUT_01;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.POS_GET_02;
import static io.gatling.javaapi.core.CoreDsl.StringBody;
import static io.gatling.javaapi.core.CoreDsl.bodyLength;
import static io.gatling.javaapi.core.CoreDsl.bodyString;
import static io.gatling.javaapi.core.CoreDsl.doIf;
import static io.gatling.javaapi.core.CoreDsl.exec;
import static io.gatling.javaapi.core.CoreDsl.scenario;
import static io.gatling.javaapi.http.HttpDsl.header;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

/**
 * Test scenarios
 */
@Slf4j
@RequiredArgsConstructor
@SuppressWarnings("unchecked") // compiler warning come from usage of Gatling API
public class EccKeyCapsuleScenarios {
    private static final Random RANDOM = new Random();

    // context path of the API (
    private static final String API_ENDPOINT = "/key-capsules";

    private final TestConfig conf;
    private final TestDataGenerator testData;
    // holds sent data for each user (used in verifying that the same data was received back)
    private final ConcurrentHashMap<Long, GeneratedCapsule> sentData = new ConcurrentHashMap<>();
    // holds received urls (with transaction ids) for created capsules
    private final Set<String> createdCapsuleUrls = ConcurrentHashMap.newKeySet();

    // key capsule transactionId min length
    private static final int MIN_TX_ID_LEN = 18;
    // key capsule transactionId max length
    private static final int MAX_TX_ID_LEN = 34;

    // Gatling session variables
    private static final String LOCATION = "location";

    ScenarioBuilder createAndGetEccKeyCapsule() {
        return scenario("Create and get capsule")
            .exec(this.createEccKeyCapsule(this.testData::generateCapsule))
            .exec(this.getAndCheckEccKeyCapsule());
    }

    //TODO: Add test for RSA-PUT_CAPSULE-POS-01-ONCE - Create ecc-details and
    // RSA-GET_CAPSULE-POS-01-CORRECT_REQUEST - Get correct ecc-details

    //TODO: Create tests for [ECC|RSA]-PUT_CAPSULE-POS-02-REPEATEDLY - Same correct capsule is sent to server
    // repetedly.

    //TODO: Create test for [ECC|RSA]-PUT-CAPSULE-POS-03-RANDOM_CONTENT - Upload random content with correct receiver
    // info (like using server for sharing file pieces)

    //TODO: create test case for PUT_CAPSULE-NEG-01-CAPSULE_TOO_BIG

    ScenarioBuilder createAndGetRecipientTransactionMismatch() {
        return scenario(NEG_GET_06 + " - Request capsule with mismatching recipient and txId")
            .exec(this.createEccKeyCapsule(this.testData::generateCapsuleWithWrongRecipient))
            .exec(this.getEccKeyCapsuleCheckTxIdMismatch());
    }

    //TODO: Add test for RSA-GET_CAPSULE-NEG-08-PUBLIC_KEY_NOT_MATCHING

    ScenarioBuilder getWithInvalidTransactionIds() {
        return scenario("Request capsule with invalid transactionId values")
            .exec(
                this.checkInvalidTransactionId(NEG_GET_02, this.testData.randomString(MIN_TX_ID_LEN)),
                this.checkInvalidTransactionId(NEG_GET_03, "123"),
                this.checkInvalidTransactionId(NEG_GET_04, ""),
                this.checkInvalidTransactionId(NEG_GET_05, this.testData.randomString(MAX_TX_ID_LEN + 1))
            )
            .exitHereIfFailed();
    }

    ScenarioBuilder createEccKeyCapsule() {
        return scenario("Create capsule").exec(
            this.createEccKeyCapsule(this.testData::generateCapsule)
        );
    }

    ScenarioBuilder getRandomEccKeyCapsule() {
        return scenario("Get random capsule").exec(this.getSavedEccKeyCapsuleIfExists);
    }

    private ChainBuilder createEccKeyCapsule(Function<Long, GeneratedCapsule> capsuleGenerator) {
        return exec(
            http(POS_PUT_01 + " - Create ecc key capsule")
                .post(this.conf.getPutServerBaseUrl() + this.API_ENDPOINT)
                .body(StringBody(session -> {
                    var userId = session.userId();
                    var capsule = capsuleGenerator.apply(userId);
                    this.sentData.put(userId, capsule);
                    return TestDataGenerator.toJson(capsule.request());
                })).asJson()
                .check(
                    status().is(HttpResponseStatus.CREATED.code()),
                    header("Location").exists().saveAs(LOCATION),
                    header("Location").transformWithSession((location, session) -> {
                        // save the created capsule urls
                        this.createdCapsuleUrls.add(location);
                        return location;
                    })
                )
        )
        .exitHereIfFailed();
    }

    private ChainBuilder getAndCheckEccKeyCapsule() {
        return exec(
            http(POS_GET_02 + " - Get correct ecc key capsule")
                .get(session -> this.conf.getGetServerBaseUrl() + session.getString(LOCATION))
                .check(
                    status().is(HttpResponseStatus.OK.code()),
                    // check that the same data we sent is returned
                    bodyString().is(session -> TestDataGenerator.toJson(
                            this.getSentData(session.userId()).request()
                        )
                    )
                )
        ).exitHereIfFailed();
    }

    private ChainBuilder getSavedEccKeyCapsuleIfExists =
        doIf(session -> !this.createdCapsuleUrls.isEmpty()).then(
            exec(
                http("Get ecc key capsule")
                    .get(session -> this.getRandomSavedCapsuleUrl())
                    .check(
                        status().in(
                            HttpResponseStatus.OK.code(), // client key matches recipient pub key
                            HttpResponseStatus.NOT_FOUND.code() // client key mismatch
                        )
                    )
            )
            .exitHereIfFailed()
        );

    private ChainBuilder getEccKeyCapsuleCheckTxIdMismatch() {
        return exec(
            http(NEG_GET_06 + " - Get ecc key capsule with wrong transactionId")
                .get(session -> this.conf.getGetServerBaseUrl() + session.getString(LOCATION))
                .check(
                    status().is(HttpResponseStatus.NOT_FOUND.code()),
                    bodyLength().is(0)
                )
        ).exitHereIfFailed();
    }

    // sends a request with the given transaction id and checks it to be handled as invalid input
    private ChainBuilder checkInvalidTransactionId(String testId, String transactionId) {
        return exec(
            http(testId + " - with invalid txId '" + transactionId + "'")
                .get(this.conf.getGetServerBaseUrl() + API_ENDPOINT + '/' + transactionId)
                .check(
                    status().is(HttpResponseStatus.NOT_FOUND.code()),
                    bodyLength().is(0)
                )
        );
    }

    private GeneratedCapsule getSentData(Long userId) {
        return Optional.ofNullable(this.sentData.get(userId))
            .orElseThrow(() -> new RuntimeException("No sent data for user " + userId));
    }

    private String getRandomSavedCapsuleUrl() {
        if (this.createdCapsuleUrls.isEmpty()) {
            throw new IllegalArgumentException("No capsule urls saved yet");
        }
        var urls = this.createdCapsuleUrls.toArray(new String[0]);
        return urls[RANDOM.nextInt(urls.length)];
    }

}
