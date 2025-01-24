package ee.cyber.cdoc2.crypto.jwt;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import jakarta.annotation.Nullable;

import java.security.cert.X509Certificate;

/**
 * JWSSigner that provides methods for getting signer identity and public certificate. Implementations are for
 * Mobile-ID and Smart-ID. Instead of providing private key,
 * it's initialized by providing signer identity (and mobile number for Mobile-ID) and signature is created using
 * remote REST API. Singer certificate is available only after successful signing.
 */
public interface IdentityJWSSigner extends JWSSigner {

    /**
     * Get signer identity, currently supported format is "etsi/SemanticsIdentifier" e.g. "etsi/PNOEE-48010010101"
     * @return signer identity who is signing the JWT using JWSSigner
     */
    EtsiIdentifier getSignerIdentifier(); // XXX: return more generic type?

    /**
     * After {@link #sign(JWSHeader, byte[])} has succeeded, signer public certificate can be queried
     * @return signer certificate if {@code sign()} has succeeded, otherwise will be {@code null}
     */
    @Nullable X509Certificate getSignerCertificate();
}
