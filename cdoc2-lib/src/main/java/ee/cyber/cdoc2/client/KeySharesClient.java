package ee.cyber.cdoc2.client;

import java.util.Optional;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;


/**
 * Client for Key Shares servers (there are few of servers).
 */
public interface KeySharesClient extends ServerClient {

    /**
     * Creates key share for {@link KeySharesCapsule for fbs.recipients.KeySharesCapsule}.
     * @param keyShare key share
     * @return created key share ID
     */
    String storeKeyShare(KeyShare keyShare) throws ExtApiException;

    /**
     * Create server nonce for authentication signature.
     * @param shareId key share ID
     * @param sessionToken CDOC2 session token (SDJWT)
     * @param signingCertificate PEM encoded certificate that signed the sessionToken
     * @return NonceResponse created server nonce response
     */
    NonceResponse createKeyShareNonce(
        String shareId,
        String sessionToken,
        String signingCertificate
    ) throws ApiException;

    /**
     * Get key share by share ID.
     * @param shareId key share ID
     * @param authToken server authentication token
     * @param authTokenSignerCert authentication token signer certificate in PEM format
     * @param sessionToken CDOC2 Session token (SDJWT)
     * @param sessionCertificate PEM encoded X509 certificate (without newlines) that was used to
     *                            generate the MID/SID signature in x-cdoc2-session-token payload.
     * @param sidRpv3SignatureParameters Base64Url-encoded JSON structure containing additional
     *                                   parameters necessary to verify the signature of
     *                                   an auth token.
     *                                   Required when the auth token is signed  with SID RPv3,
     *                                   omitted otherwise.  (optional)
     * @return KeyShare key share
     */
    Optional<KeyShare> getKeyShare(
        String shareId,
        String authToken,
        String authTokenSignerCert,
        String sessionToken,
        String sessionCertificate,
        String sidRpv3SignatureParameters,
        Cdoc2KeySharesApiClient.RpCountersignatureParams countersignatureParams
    )
        throws ExtApiException;

}
