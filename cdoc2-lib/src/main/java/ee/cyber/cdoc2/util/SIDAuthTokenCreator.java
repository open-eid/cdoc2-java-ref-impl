package ee.cyber.cdoc2.util;

import com.nimbusds.jose.JOSEException;
import ee.cyber.cdoc2.auth.AuthTokenCreator;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.exceptions.AuthSignatureCreationException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

/**
 * Class to create key-shares auth token
 */
public class SIDAuthTokenCreator {

    KeyShareClientFactory sharesClientFac;
    SIDAuthJWSSigner jwsSigner;

    // used for "iss" field in JWT body
    EtsiIdentifier authenticatorSemID; // as etsi/PNOEE-48010010101
    List<KeyShareUri> shareUris;

    AuthTokenCreator authTokenCreator;
    X509Certificate authenticatorCert;

    /**
     * Create signature for key shares auth token. <code>authenticator</code> AUTH key is used for signing.
     * @param authenticator ETSI Natural Person Semantics Identifier as example
     *                      "PNOEE-48010010101"
     * @param shareUris key share uris that are accessed
     * @param fac KeyShareClientFactory used to create key share nonces that are signed
     */
    public SIDAuthTokenCreator(String authenticator,
                               List<KeyShareUri> shareUris,
                               KeyShareClientFactory fac,
                               SmartIdClient sidClient) throws AuthSignatureCreationException {

        this.sharesClientFac = fac;
        this.jwsSigner = new SIDAuthJWSSigner(sidClient, new SemanticsIdentifier(authenticator));
        this.authenticatorSemID = new EtsiIdentifier("etsi/" + authenticator);
        this.shareUris = shareUris;

        try {
            this.authTokenCreator = prepare();
            this.authenticatorCert = jwsSigner.getSignerCertificate();
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
     * Prepare data to be signed and sign the data with the SIDAuthJWSSigner.
     * {@link SIDAuthJWSSigner#getSignerCertificate()} will get public certificate instance that was used for
     * signing
     * @return signed AuthTokenCreator (data is signed)
     * @throws ApiException
     * @throws ParseException
     * @throws JOSEException
     */
    AuthTokenCreator prepare() throws ApiException, ParseException, JOSEException {
        List<ShareAccessData> audArray = new LinkedList<>();

        for (KeyShareUri shareUri: shareUris) {
            ShareAccessData accessData = createNonce(shareUri, sharesClientFac);
            audArray.add(accessData);
        }

        AuthTokenCreator tokenCreator = AuthTokenCreator.builder()
            .withEtsiIdentifier(authenticatorSemID)
            .withSharesAccessData(audArray)
            .build();

        tokenCreator.sign(jwsSigner,
            jwsSigner.getSignerSemID().getIdentifier() // PNOEE-30303039914, used for JWT header.kid,
                                                       // should match authenticator cert subjectDN->serialnumber
        );

        return tokenCreator;
    }

    /**
     * Create nonce for shareId using keyShareClient that will be signed as part of SDJWT
     * @param shareUri  shareId in server
     * @param fac to get reference to KeyShareClient specific to shares server
     * @return nonce created for shareId by shares-server
     * @throws ApiException
     */
    ShareAccessData createNonce(KeyShareUri shareUri, KeyShareClientFactory fac) throws ApiException {

        KeySharesClient shareClient = fac.getClientForServerUrl(shareUri.serverBaseUrl());
        NonceResponse nonceResponse = shareClient.createKeyShareNonce(shareUri.shareId());
        byte[] nonceBytes = nonceResponse.getNonce();

        //TODO: auth expect nonce as string, but generated client returns it as bytes[] - update OpenAPI
        //see https://rm.ext.cyber.ee/redmine/issues/4211
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);

        return new ShareAccessData(shareUri.serverBaseUrl(), shareUri.shareId(), nonce);
    }
}
