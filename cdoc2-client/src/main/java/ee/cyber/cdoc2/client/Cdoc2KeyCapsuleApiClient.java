package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.ApiResponse;
import ee.cyber.cdoc2.client.api.Cdoc2KeyCapsulesApi;
import ee.cyber.cdoc2.client.model.Capsule;

import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc2.client.ApiClientUtil.STATUS_CODE_NOT_FOUND;
import static ee.cyber.cdoc2.client.ApiClientUtil.extractIdFromHeader;


/**
 * Client for creating and getting CDOC2 key capsules from key server.
 * Provides Builder to initialize mutual TLS from PKCS11 (smart-card) or PKCS12 (software) key
 * stores.
 */
public final class Cdoc2KeyCapsuleApiClient extends KeyCapsuleClientBuilder {

    private static final Logger log = LoggerFactory.getLogger(Cdoc2KeyCapsuleApiClient.class);

    private final Cdoc2KeyCapsulesApi capsulesApi;

    Cdoc2KeyCapsuleApiClient(Cdoc2KeyCapsulesApi capsuleApi) {
        this.capsulesApi = capsuleApi;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Cdoc2KeyCapsuleApiClient that = (Cdoc2KeyCapsuleApiClient) o;
        return capsulesApi.equals(that.capsulesApi);
    }

    @Override
    public int hashCode() {
        return Objects.hash(capsulesApi);
    }

    public static KeyCapsuleClientBuilder builder() {
        return new KeyCapsuleClientBuilder();
    }

    /**
     * @param capsule key capsule from openAPI
     * @return transactionId transaction ID
     * @throws ApiException if Key capsule creation has failed
     */
    public String createCapsule(Capsule capsule) throws ApiException {
        return createCapsule(capsule, null);
    }

    /**
     * @param capsule key capsule
     * @param xExpiryTime capsule expiry time (optional)
     * @return transactionId
     * @throws ApiException if capsule creation has failed
     */
    public String createCapsule(Capsule capsule, @Nullable OffsetDateTime xExpiryTime) throws ApiException {
        Objects.requireNonNull(capsule);
        Objects.requireNonNull(capsule.getCapsuleType());
        if (capsule.getCapsuleType() == Capsule.CapsuleTypeEnum.UNKNOWN_DEFAULT_OPEN_API) {
            throw new IllegalArgumentException("Illegal capsuleType " + capsule.getCapsuleType());
        }
        Objects.requireNonNull(capsule.getRecipientId());
        Objects.requireNonNull(capsule.getEphemeralKeyMaterial());

        ApiResponse<Void> response = capsulesApi.createCapsuleWithHttpInfo(capsule, xExpiryTime);

        return extractIdFromHeader(response, "EccDetails", "transactionId", log);
    }

    /**
     * @param transactionId transaction ID
     * @return Optional with value, if server returned 200 or empty Optional if 404
     * @throws ApiException if http response code is something else that 200 or 404
     */
    public Optional<Capsule> getCapsule(String transactionId) throws ApiException {
        if (transactionId == null) {
            throw new IllegalArgumentException("transactionId cannot be null");
        }

        try {
            ApiResponse<Capsule> response
                = capsulesApi.getCapsuleByTransactionIdWithHttpInfo(transactionId);
            return Optional.of(response.getData());
        } catch (ApiException ex) {
            log.error("Key capsule get request with transaction ID {} has failed with error code {}",
                transactionId, ex.getCode());
            if (ex.getCode() == STATUS_CODE_NOT_FOUND) {
                return Optional.empty();
            } else {
                log.error("Unexpected status code {}", ex.getCode());
                throw ex;
            }
        }
    }

}
