package ee.cyber.cdoc20.server;

import io.gatling.javaapi.core.ChainBuilder;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.netty.handler.codec.http.HttpResponseStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_02;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_03;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_04;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_05;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_06;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.NEG_07;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.POS_01;
import static ee.cyber.cdoc20.server.ScenarioIdentifiers.POS_02;
import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.*;

/**
 * Test scenarios
 */
@Slf4j
@RequiredArgsConstructor
@SuppressWarnings("unchecked") // compiler warning come from usage of Gatling API
public class EccDetailsScenarios {
    private static final Random RANDOM = new Random();

    // context path of the ecc-details  API (
    private static final String ECC_DETAILS_API = "/ecc-details";

    private final TestDataGenerator testData;
    // holds sent data for each user (used in verifying that the same data was received back)
    private final ConcurrentHashMap<Long, GeneratedCapsule> sentData = new ConcurrentHashMap<>();
    // holds received urls (with transaction ids) for created capsules
    private final Set<String> createdCapsuleUrls = ConcurrentHashMap.newKeySet();

    // Gatling session variables
    private static final String LOCATION = "location";

    ScenarioBuilder createAndGetCreateEccDetails() {
        return scenario("Create and get capsule")
            .exec(this.createEccDetails(this.testData::generateCapsule))
            .exec(this.getAndCheckEccDetails);
    }

    //TODO: Add test for RSA-PUT_CAPSULE-POS-01-ONCE - Create ecc-details and
    // RSA-GET_CAPSULE-POS-01-CORRECT_REQUEST - Get correct ecc-details

    //TODO: Create tests for [ECC|RSA]-PUT_CAPSULE-POS-02-REPEATEDLY - Same correct capsule is sent to server
    // repetedly.

    //TODO: Create test for [ECC|RSA]-PUT-CAPSULE-POS-03-RANDOM_CONTENT - Upload random content with correct receiver
    // info (like using server for sharing file pieces)

    //TODO: create test case for PUT_CAPSULE-NEG-01-CAPSULE_TOO_BIG


    ScenarioBuilder createAndGetRecipientTransactionMismatch() {
        return scenario(NEG_07 + " - Request capsule with mismatching recipient and txId")
            .exec(this.createEccDetails(this.testData::generateCapsuleWithWrongRecipient))
            .exec(this.getEccDetailsTxIdMismatch);
    }

    //TODO: Add test for RSA-GET_CAPSULE-NEG-08-PUBLIC_KEY_NOT_MATCHING

    ScenarioBuilder getWithInvalidTransactionIds() {
        return scenario("Request capsule with invalid transactionId values")
            .exec(
                this.checkInvalidTransactionId(NEG_02, "SD" + UUID.randomUUID()),
                this.checkInvalidTransactionId(NEG_03, UUID.randomUUID().toString()),
                this.checkInvalidTransactionId(NEG_04, "123"),
                this.checkInvalidTransactionId(NEG_05, ""),
                this.checkInvalidTransactionId(NEG_06,
                    String.join("-", UUID.randomUUID().toString(), UUID.randomUUID().toString())
                )
            )
            .exitHereIfFailed();
    }

    ScenarioBuilder createEccDetails() {
        return scenario("Create capsule").exec(
            this.createEccDetails(this.testData::generateCapsule)
        );
    }

    ScenarioBuilder getRandomEccDetails() {
        return scenario("Get random capsule").exec(this.getSavedEccDetailsIfExists);
    }

    private ChainBuilder createEccDetails(Function<Long, GeneratedCapsule> capsuleGenerator) {
        return exec(
            http(POS_01 + " - Create ecc-details")
                .post(ECC_DETAILS_API)
                .body(StringBody(session -> {
                    var userId = session.userId();
                    var capsule = capsuleGenerator.apply(userId);
                    this.sentData.put(userId, capsule);
                    return TestDataGenerator.toJson(capsule.getRequest());
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
    private ChainBuilder getAndCheckEccDetails =
        exec(
            http(POS_02 + " - Get correct ecc-details")
                .get(session -> session.getString(LOCATION))
                .check(
                    status().is(HttpResponseStatus.OK.code()),
                    // check that the same data we sent is returned
                    bodyString().is(session -> TestDataGenerator.toJson(
                            this.getSentData(session.userId()).getRequest()
                        )
                    )
                )
        )
        .exitHereIfFailed();

    private ChainBuilder getSavedEccDetailsIfExists =
        doIf(session -> !this.createdCapsuleUrls.isEmpty()).then(
            exec(
                http("Get ecc-details")
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

    private ChainBuilder getEccDetailsTxIdMismatch =
        exec(
            http("Get ecc-details for wrong transactionId")
                .get(session -> session.getString(LOCATION))
                .check(
                    status().is(HttpResponseStatus.NOT_FOUND.code()),
                    bodyLength().is(0)
                )
        )
        .exitHereIfFailed();
    // sends a request with the given transaction id and checks it to be handled as invalid input
    private ChainBuilder checkInvalidTransactionId(String testId, String transactionId) {
        return exec(
            http(testId + " - with invalid txId '" + transactionId + "'")
                .get(ECC_DETAILS_API + '/' + transactionId)
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
