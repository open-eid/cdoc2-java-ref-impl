package ee.cyber.cdoc20.server.api;

import ee.cyber.cdoc20.server.model.Capsule;
import ee.cyber.cdoc20.server.model.db.KeyCapsuleDb;
import ee.cyber.cdoc20.server.model.db.KeyCapsuleRepository;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.NativeWebRequest;
import static ee.cyber.cdoc20.server.Utils.getPathAndQueryPart;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

/**
 * Implements API for creating CDOC2.0 key capsules {@link KeyCapsulesApi}
 */
@Service
@Slf4j
public class CreateKeyCapsuleApi implements KeyCapsulesApiDelegate {

    @Autowired
    private NativeWebRequest nativeWebRequest;

    @Autowired
    private KeyCapsuleRepository keyCapsuleRepository;

    @Override
    public Optional<NativeWebRequest> getRequest() {
        return Optional.of(nativeWebRequest);
    }

    @Override
    public ResponseEntity<Void> createCapsule(Capsule capsule) {
        log.trace("createCapsule(type={}, recipientId={} bytes, ephemeralKey={} bytes)",
            capsule.getCapsuleType(), capsule.getRecipientId().length,
            capsule.getEphemeralKeyMaterial().length
        );

        if (!CapsuleValidator.isValid(capsule)) {
            return ResponseEntity.badRequest().build();
        }

        try {
            var saved = this.keyCapsuleRepository.save(
                new KeyCapsuleDb()
                    .setCapsuleType(getDbCapsuleType(capsule.getCapsuleType()))
                    .setRecipient(capsule.getRecipientId())
                    .setPayload(capsule.getEphemeralKeyMaterial())
            );

            log.info(
                "Capsule(transactionId={}, type={}) created",
                saved.getTransactionId(), saved.getCapsuleType()
            );

            URI created = getResourceLocation(saved.getTransactionId());

            return ResponseEntity.created(created).build();
        } catch (Exception e) {
            log.error(
                "Failed to save key capsule(type={}, recipient={}, payloadLength={})",
                capsule.getCapsuleType(),
                Base64.getEncoder().encodeToString(capsule.getRecipientId()),
                capsule.getEphemeralKeyMaterial().length,
                e
            );
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<Capsule> getCapsuleByTransactionId(String transactionId) {
        log.error("getCapsuleByTransactionId() operation not supported on key capsule put server");
        return new ResponseEntity<>(HttpStatus.METHOD_NOT_ALLOWED);
    }

    /**
     * Get URI for getting Key Capsule resource (Location).
     * @param id Capsule id example: KC9b7036de0c9fce889850c4bbb1e23482
     * @return URI (path and query) example: /key-capsules/KC9b7036de0c9fce889850c4bbb1e23482
     * @throws URISyntaxException
     */
    private static URI getResourceLocation(String id) throws URISyntaxException {
        return getPathAndQueryPart(
            linkTo(methodOn(KeyCapsulesApiController.class).getCapsuleByTransactionId(id)).toUri()
        );
    }

    private static KeyCapsuleDb.CapsuleType getDbCapsuleType(Capsule.CapsuleTypeEnum dtoType) {
        switch (dtoType) {
            case ECC_SECP384R1:
                return KeyCapsuleDb.CapsuleType.SECP384R1;
            case RSA:
                return KeyCapsuleDb.CapsuleType.RSA;
            default:
                throw new IllegalArgumentException("Unknown capsule type: " + dtoType);
        }
    }
}
