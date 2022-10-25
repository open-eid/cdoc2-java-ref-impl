package ee.cyber.cdoc20.server.api;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.AbstractConverter;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.NativeWebRequest;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.server.model.ServerEccDetails;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpa;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpaRepository;

import static ee.cyber.cdoc20.server.OpenApiUtil.fixOABrokenBaseURL;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

/**
 * Implement /ecc-details APIs {@link EccDetailsApi}
 */
@Service
@Slf4j
public class EccDetailsApiDelegateImpl implements EccDetailsApiDelegate {

    @Autowired
    private final NativeWebRequest nativeWebRequest;

    @Autowired
    private ServerEccDetailsJpaRepository jpaRepository;

    private static ModelMapper modelMapperInstance = null;


    EccDetailsApiDelegateImpl(NativeWebRequest nativeWebRequest) {
        this.nativeWebRequest = nativeWebRequest;
    }

    @Override
    public Optional<NativeWebRequest> getRequest() {
        return Optional.of(nativeWebRequest);
    }

    /**
     * POST /ecc-details/{transactionId} : Add Ecc Details
     * Save ServerEccDetails and generate transaction id using secure random. Saved resource location
     * is returned in Location header
     *
     * Location: /ecc-details/SD9b7036de0c9fce889850c4bbb1e23482
     *
     * @param serverEccDetails (optional)
     * @return Created (status code 201)
     *         or Bad request. Client error. (status code 400)
    * @see EccDetailsApi#createEccDetails
     */
    @Override
    public ResponseEntity<Void> createEccDetails(ServerEccDetails serverEccDetails) {
        log.trace("createEccDetails");

        if (!isValid(serverEccDetails)) {
            return ResponseEntity.badRequest().build();
        }

        try {
            ServerEccDetailsJpa jpaModel =
                    getModelMapperInstance().map(serverEccDetails, ServerEccDetailsJpa.class);
            var saved = jpaRepository.save(jpaModel);

            log.debug("serverEccDetails   : {} {}", Base64.getEncoder().encodeToString(serverEccDetails.getRecipientPubKey()),
                    HexFormat.of().formatHex(serverEccDetails.getRecipientPubKey()));
            log.debug("ServerEccDetailsJpa: {} {}",jpaModel.getRecipientPubKey(),
                    HexFormat.of().formatHex(Base64.getDecoder().decode(jpaModel.getRecipientPubKey())));

            URI created = getResourceLocation(saved.getTransactionId());

            return ResponseEntity.created(created).build();
        } catch (URISyntaxException e) {
            log.error("failed to publish {}", serverEccDetails, e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
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
                    && ECKeys.isEcSecp384r1Curve((ECPublicKey) clientPubKey)
                    && (detailsJpa = jpaRepository.findById(transactionId)).isPresent()) {

                ServerEccDetails details = getModelMapperInstance().map(detailsJpa.get(), ServerEccDetails.class);

                log.debug("Recipient pub key: {}", Base64.getEncoder().encodeToString(details.getRecipientPubKey()));

                if (Arrays.equals(details.getRecipientPubKey(), ECKeys.encodeEcPubKeyForTls((ECPublicKey) clientPubKey))) {
                    log.info("Found {} for {} and client certificate", detailsJpa.get(), transactionId);
                    return ResponseEntity.ok(details);
                } else {
                    log.info("Client certificate {} doesn't match to recipient public key {}",
                            clientCert.getSubjectDN().getName(), Base64.getEncoder().encodeToString(details.getRecipientPubKey()));
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

    /**
     * Get URI for getting ECC details resource (Location).
     * @param id EccDetails id example: SD9b7036de0c9fce889850c4bbb1e23482
     * @return URI (path and query) example: /ecc-details/SD9b7036de0c9fce889850c4bbb1e23482
     * @throws URISyntaxException
     */
    private static URI getResourceLocation(String id) throws URISyntaxException {
        return fixOABrokenBaseURL(linkTo(methodOn(EccDetailsApiController.class).getEccDetailsByTransactionId(id)).toUri());
    }

    private boolean isValid(ServerEccDetails sd) {
        try {
            if (sd.getEccCurve() != null) {
                ECKeys.EllipticCurve curve = ECKeys.EllipticCurve.forValue(sd.getEccCurve().byteValue());

                int tlsEncodedKeyLen = 2 * curve.getKeyLength() + 1;
                if ((sd.getRecipientPubKey() == null) || (sd.getRecipientPubKey().length != tlsEncodedKeyLen)
                    || (sd.getSenderPubKey() == null) || (sd.getSenderPubKey().length != tlsEncodedKeyLen)) {
                    log.info("Invalid key length for curve {}", curve.getName());
                    return false;
                }

                ECPublicKey recipientPubKey = curve.decodeFromTls(ByteBuffer.wrap(sd.getRecipientPubKey()));
                ECPublicKey senderPubKey = curve.decodeFromTls(ByteBuffer.wrap(sd.getSenderPubKey()));

                return (curve.isValidKey(recipientPubKey) && curve.isValidKey(senderPubKey));
            }
        } catch (NoSuchAlgorithmException nsae) {
            log.info("Invalid curve " + nsae);
        } catch (GeneralSecurityException gse) {
            log.info("Invalid key " + gse);
        }

        return false;
    }

    /**
     * ModelMapper to convert between {@link ServerEccDetails} and {@link ServerEccDetailsJpa} models
     */
    static ModelMapper getModelMapperInstance() {
        if (modelMapperInstance == null) {
            modelMapperInstance = new ModelMapper();
            Converter<byte[], String> byteArrayToBase64Converter = new AbstractConverter<>() {
                @Override
                protected String convert(byte[] bytes) {
                    return Base64.getEncoder().encodeToString(bytes);
                }
            };

            Converter<String, byte[]> base64ToByteArrayConverter = new AbstractConverter<>() {
                @Override
                protected byte[] convert(String base64) {
                    return Base64.getDecoder().decode(base64);
                }
            };

            modelMapperInstance.addConverter(byteArrayToBase64Converter);
            modelMapperInstance.addConverter(base64ToByteArrayConverter);
        }
        return modelMapperInstance;
    }
}
