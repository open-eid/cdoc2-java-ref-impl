package ee.cyber.cdoc20.server.model;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.Id;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import ee.cyber.cdoc20.crypto.Crypto;

@Data
@Entity
@Table(name = "server_ecc_details")
@Slf4j
@EntityListeners(AuditingEntityListener.class)
public class ServerEccDetailsJpa {

    @PrePersist
    private void genTransactionId() {
        byte[] sRnd = new byte[16];
        try {
            if (this.transactionId == null) {
                Crypto.getSecureRandom().nextBytes(sRnd);
                this.transactionId = String.format("SD%s", HexFormat.of().formatHex(sRnd));
            }
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            log.error("SecureRandom not initialized", noSuchAlgorithmException);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, noSuchAlgorithmException.toString());
        }
    }

    @Id
    @Column(length = 34)
    @Size(max = 34)
    private String transactionId;

    @NotNull
    @Column(nullable = false)
    @Size(max = 132) //secp384r1 base64 TLS encoded (97bytes) EC public key
    private String recipientPubKey;

    @NotNull
    @Column(nullable = false)
    @Size(max = 132) //secp384r1 base64 TLS encoded (97bytes) EC public key
    private String senderPubKey;

    @Column(columnDefinition = "SMALLINT", nullable = false)
    @NotNull
    private Integer eccCurve;

    @CreatedDate
    private Instant createdAt;
}
