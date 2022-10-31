package ee.cyber.cdoc20.server.api;

import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.server.model.ServerEccDetails;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpa;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpaRepository;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.NativeWebRequest;
import static ee.cyber.cdoc20.server.Utils.MODEL_MAPPER;

/**
 * Implements API for getting CDOC2.0 key capsules {@link EccDetailsApi}
 */
@Service
@Slf4j
public class GetKeyCapsuleApi implements EccDetailsApiDelegate {

    @Autowired
    private final NativeWebRequest nativeWebRequest;

    @Autowired
    private ServerEccDetailsJpaRepository jpaRepository;

    private static ModelMapper modelMapperInstance = null;

    GetKeyCapsuleApi(NativeWebRequest nativeWebRequest) {
        this.nativeWebRequest = nativeWebRequest;
    }

    @Override
    public Optional<NativeWebRequest> getRequest() {
        return Optional.of(nativeWebRequest);
    }

    @Override
    public ResponseEntity<Void> createEccDetails(ServerEccDetails serverEccDetails) {
        log.error("createEccDetails() operation not supported on get capsule server");
        return new ResponseEntity<>(HttpStatus.METHOD_NOT_ALLOWED);
    }

    @Override
    public ResponseEntity<ServerEccDetails> getEccDetailsByTransactionId(String transactionId) {
        log.trace("getEccDetailsByTransactionId({})", transactionId);

        X509Certificate clientCert;
        HttpServletRequest req = nativeWebRequest.getNativeRequest(HttpServletRequest.class);
        X509Certificate[] certs = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
        if (certs.length > 0) {
            clientCert = certs[0];
            log.debug("Got cert: {}", clientCert.getSubjectDN().getName());
        } else {
            log.info("No cert");
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        try {
            PublicKey clientPubKey = clientCert.getPublicKey();

            String clientKeyB64 = Base64.getEncoder().encodeToString(
                    ECKeys.encodeEcPubKeyForTls((ECPublicKey) clientPubKey));
            log.debug("client pub key base64 {}", clientKeyB64);

            Optional<ServerEccDetailsJpa> detailsJpa = Optional.empty();
            if ("EC".equals(clientPubKey.getAlgorithm())
                    && ECKeys.isEcSecp384r1Curve((ECPublicKey) clientPubKey)) {
                detailsJpa = jpaRepository.findById(transactionId);
                if (detailsJpa.isPresent()) {
                    ServerEccDetails details = MODEL_MAPPER.map(detailsJpa.get(), ServerEccDetails.class);

                    log.debug("Recipient pub key: {}",
                        Base64.getEncoder().encodeToString(details.getRecipientPubKey())
                    );

                    if (Arrays.equals(
                            details.getRecipientPubKey(),
                            ECKeys.encodeEcPubKeyForTls((ECPublicKey) clientPubKey))) {
                        log.info("Found {} for {} and client certificate", detailsJpa.get(), transactionId);
                        return ResponseEntity.ok(details);
                    } else {
                        log.info("Client certificate {} doesn't match to recipient public key {}",
                            clientCert.getSubjectDN().getName(),
                            Base64.getEncoder().encodeToString(details.getRecipientPubKey())
                        );
                    }
                }
            }
            log.info("Certificate {} doesn't contain valid public key or no details found for {}",
                    clientCert.getSubjectDN().getName(), transactionId);
            log.debug("Details for {}: {}", transactionId, detailsJpa);
            log.debug("Certificate: {}", clientCert);
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        } catch (GeneralSecurityException gse) {
            log.error("GeneralSecurityException", gse);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
