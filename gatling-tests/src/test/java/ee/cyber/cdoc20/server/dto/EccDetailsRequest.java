package ee.cyber.cdoc20.server.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import com.fasterxml.jackson.annotation.JsonProperty;


/**
 * Ecc Details request DTO
 */
@Getter
@AllArgsConstructor
public class EccDetailsRequest {
    /**
     * Base64 encoded key
     */
    @JsonProperty("recipient_pub_key")
    private String recipientPubKey;

    /**
     * Base64 encoded key
     */
    @JsonProperty("sender_pub_key")
    private String senderPubKey;

    @JsonProperty("ecc_curve")
    private Integer eccCurve;
}
