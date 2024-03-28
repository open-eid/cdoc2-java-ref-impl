package ee.cyber.cdoc2.server.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * CDOC2 key capsule request DTO
 */
@Getter
@AllArgsConstructor
public class KeyCapsuleRequest {

    /**
     * Base64 encoded public key
     */
    @JsonProperty("recipient_id")
    private String recipientId;

    /**
     * Base64 encoded key material
     */
    @JsonProperty("ephemeral_key_material")
    private String ephemeralKeyMaterial;

    @JsonProperty("capsule_type")
    private KeyCapsuleType capsuleType;
}
