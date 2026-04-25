package ee.cyber.cdoc2.crypto.jwt;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.jose.JOSEException;

import ee.cyber.cdoc2.auth.AuthTokenCreator;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.exceptions.AuthSignatureCreationException;


/**
 * Class to create key-shares auth token (sd-jwt) with MID/SID.
 */
public class SidMidAuthTokenCreator {

    KeySharesClientFactory sharesClientFac;
    IdentityJWSSigner idJwsSigner;

    List<KeyShareUri> shareUris;

    AuthTokenCreator authTokenCreator;
    X509Certificate authenticatorCert;
    SessionToken sessionToken;
    String sidRpV3SignatureParameters;

    /**
     * Create signature for key shares auth token. Uses {@link IdentityJWSSigner} to create
     * signature using Smart-ID ({@link SIDAuthJWSSigner})
     * or Mobile-ID ({@link MIDAuthJWSSigner}) REST APIs
     * @param idJwsSigner {@link IdentityJWSSigner} that implements signing either
     *                                                                   with Smart-ID or Mobile-ID
     * @param shareUris     key share uris that are accessed
     * @param fac           KeyShareClientFactory used to create key share nonces that are signed
     * @param sessionToken  cdoc2 session token
     * @throws AuthSignatureCreationException if signature creation fails
     */
    public SidMidAuthTokenCreator(
        IdentityJWSSigner idJwsSigner,
        List<KeyShareUri> shareUris,
        KeySharesClientFactory fac,
        SessionToken sessionToken
    )  throws AuthSignatureCreationException {

        this.sharesClientFac = fac;
        this.idJwsSigner = idJwsSigner;
        this.shareUris = shareUris;
        this.sessionToken = sessionToken;

        try {
            this.authTokenCreator = prepare();
            this.authenticatorCert = idJwsSigner.getSignerCertificate();
            this.sidRpV3SignatureParameters = idJwsSigner.getSignatureValidationParamsBase64Url();
        } catch (ApiException | JOSEException | ParseException ex) {
            throw new AuthSignatureCreationException(ex);
        }
    }

    public SessionToken getSessionToken() {
        return this.sessionToken;
    }

    /**
     * Additional parameters needed to verify a SID RpV3 ACSP_V2 signature.
     * {@code null} for MID-signed tokens
     * @return Base64Url-encoded JSON structure or {@code null} for MID
     */
    public String getSidRpV3SignatureParameters() {
        return this.sidRpV3SignatureParameters;
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

        X509Certificate certificate = this.authenticatorCert;
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
        String disclosedSessionToken = "";
        String signingCertificate = "";
        // TODO: This is not implemented for MiD yet, so the token might be null,
        //  remove this once session token is implemented for MiD
        if (sessionToken != null) {
            disclosedSessionToken = this.sessionToken.getSessionToken(shareUri);
            signingCertificate = this.sessionToken.signingCertificate;
        }

        KeySharesClient shareClient = fac.getClientForServerUrl(shareUri.serverBaseUrl());
        NonceResponse nonceResponse = shareClient.createKeyShareNonce(
            shareUri.shareId(), disclosedSessionToken, signingCertificate
        );
        String nonce = nonceResponse.getNonce();

        return new ShareAccessData(shareUri.serverBaseUrl(), shareUri.shareId(), nonce);
    }

}
