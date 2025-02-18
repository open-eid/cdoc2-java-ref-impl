package ee.cyber.cdoc2.crypto.jwt;

import com.nimbusds.jose.JOSEException;
import ee.cyber.cdoc2.auth.AuthTokenCreator;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.exceptions.AuthSignatureCreationException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;


/**
 * Class to create key-shares auth token (sd-jwt) with MID/SID.
 */
public class SidMidAuthTokenCreator {

    KeySharesClientFactory sharesClientFac;
    IdentityJWSSigner idJwsSigner;

    List<KeyShareUri> shareUris;

    AuthTokenCreator authTokenCreator;
    X509Certificate authenticatorCert;

    /**
     * Create signature for key shares auth token. Uses {@link IdentityJWSSigner} to create
     * signature using Smart-ID ({@link SIDAuthJWSSigner})
     * or Mobile-ID ({@link MIDAuthJWSSigner}) REST APIs
     * @param idJwsSigner {@link IdentityJWSSigner} that implements signing either
     *                                                                   with Smart-ID or Mobile-ID
     * @param shareUris key share uris that are accessed
     * @param fac KeyShareClientFactory used to create key share nonces that are signed
     * @throws AuthSignatureCreationException if signature creation fails
     */
    public SidMidAuthTokenCreator(
        IdentityJWSSigner idJwsSigner,
        List<KeyShareUri> shareUris,
        KeySharesClientFactory fac
    )  throws AuthSignatureCreationException {

        this.sharesClientFac = fac;
        this.idJwsSigner = idJwsSigner;
        this.shareUris = shareUris;

        try {
            this.authTokenCreator = prepare();
            this.authenticatorCert = idJwsSigner.getSignerCertificate();
        } catch (ApiException | JOSEException | ParseException ex) {
            throw new AuthSignatureCreationException(ex);
        }
    }

    /**
     * Create token (sdjwt) for share id
     * @param shareID shareId from signed shareAccessData
     * @return ticket as SDJWT
     * @throws IllegalArgumentException if shareId was not part signed payload
     */
    public String getTokenForShareID(String shareID) {
        return authTokenCreator.createTicketForShareId(shareID);
    }

    /**
     * Authenticator certificate that was used to sign the token
     * @return certificate that was used to sign the SDJWT
     */
    public X509Certificate getAuthenticatorCert() {
        return authenticatorCert;
    }

    /**
     * Authenticator certificate that was used to sign the token as single line PEM
     * @return base64 encoded PEM certificate
     * @throws CertificateEncodingException if certificate encoding fails
     */
    public String getAuthenticatorCertPEM() throws CertificateEncodingException {

        X509Certificate certificate = getAuthenticatorCert();
        return (certificate == null) ? null
            : "-----BEGIN CERTIFICATE-----"
              + Base64.getEncoder().encodeToString(certificate.getEncoded())
              + "-----END CERTIFICATE-----";
    }

    /**
     * Prepare data to be signed and sign the data with the SIDAuthJWSSigner.
     * {@link SIDAuthJWSSigner#getSignerCertificate()} will get public certificate instance that
     * was used for signing
     * @return signed AuthTokenCreator (data is signed)
     * @throws ApiException if server nonce creation fails
     * @throws ParseException if server nonce creation fails
     * @throws JOSEException if server nonce creation fails
     */
    AuthTokenCreator prepare() throws ApiException, ParseException, JOSEException {
        List<ShareAccessData> audArray = new LinkedList<>();

        for (KeyShareUri shareUri: shareUris) {
            ShareAccessData accessData = createNonce(shareUri, sharesClientFac);
            audArray.add(accessData);
        }

        AuthTokenCreator tokenCreator = AuthTokenCreator.builder()
            .withEtsiIdentifier(idJwsSigner.getSignerIdentifier())
            .withSharesAccessData(audArray)
            .build();

        tokenCreator.sign(idJwsSigner);

        return tokenCreator;
    }

    /**
     * Create nonce for shareId using keyShareClient that will be signed as part of SDJWT.
     * @param shareUri shareId in server
     * @param fac to get reference to KeyShareClient specific to shares server
     * @return nonce created for shareId by shares-server
     * @throws ApiException if server nonce creation fails
     */
    ShareAccessData createNonce(KeyShareUri shareUri, KeySharesClientFactory fac) throws ApiException {

        KeySharesClient shareClient = fac.getClientForServerUrl(shareUri.serverBaseUrl());
        NonceResponse nonceResponse = shareClient.createKeyShareNonce(shareUri.shareId());
        String nonce = nonceResponse.getNonce();

        return new ShareAccessData(shareUri.serverBaseUrl(), shareUri.shareId(), nonce);
    }

}
