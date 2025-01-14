package ee.cyber.cdoc2.util;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ee.cyber.cdoc2.crypto.KeyAlgorithm;


/**
 * Methods for parsing Smart-ID certificate
 * @see <a href="https://www.skidsolutions.eu/wp-content/uploads/2024/10/SK-CPR-SMART-ID-EN-v4_7-20241127.pdf">
 *     Certificate and OCSP Profile for Smart-ID v4.7</a>
 */
public class SIDAuthCertData extends AuthenticationIdentity {

    private static final Logger log = LoggerFactory.getLogger(SIDAuthCertData.class);

    private AuthenticationIdentity authIdentity;

    // PNOEE-47101010033
    private String semanticsIdentifier;

    SIDAuthCertData(AuthenticationIdentity authenticationIdentity, String semanticsIdentifier) {
        this.authIdentity = authenticationIdentity;
        this.semanticsIdentifier = semanticsIdentifier;
    }

    /**
     * Parse data from Smart-ID certificate
     * @param sidCert certificate for Smart-ID
     * @return SIDCertData parsed from smart-id certificate
     * @throws SmartIdClientException if certificate parsing fails
     */
    public static SIDAuthCertData parse(X509Certificate sidCert)  {
        AuthenticationIdentity authIdentity = AuthenticationResponseValidator.constructAuthenticationIdentity(sidCert);
        String semanticsIdentifier = parseSemanticsIdentifier(sidCert);
        return new SIDAuthCertData(authIdentity, semanticsIdentifier);
    }

    /**
     * Parse serialNumber from certificate subjectDN serialNumber
     * (example subjectDN='SERIALNUMBER=PNOEE-30303039914, GIVENNAME=OK, SURNAME=TESTNUMBER, CN="TESTNUMBER,OK", C=EE')
     * @param sidCert smart-id certificate
     * @return semanticsIdentifier as String (for example PNOEE-37807156011)
     */
    public static String parseSemanticsIdentifier(X509Certificate sidCert) {
        X500Principal subjectX500Principal = sidCert.getSubjectX500Principal();
        var knownOids = Map.of(
            "2.5.4.5", "serialNumber",
            "2.5.4.42", "givenName",
            "2.5.4.4", "surname");

        // X500Principal in Java 17 doesn't know about knowOids, although deprecated getSubjectDN is able to parse those
        // subjectDN='SERIALNUMBER=PNOEE-30303039914, GIVENNAME=OK, SURNAME=TESTNUMBER, CN="TESTNUMBER,OK", C=EE'
        String subjectDN = subjectX500Principal.getName(X500Principal.RFC2253, knownOids);

        try {
            LdapName ln = new LdapName(subjectDN);

            for (Rdn rdn : ln.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("serialNumber")) {
                    return rdn.getValue().toString();
                }
            }
            log.warn("serialNumber not found from subjectDN {}", subjectDN);
        } catch (InvalidNameException ine) {
            throw new SmartIdClientException("Error getting serialNumber from certificate subjectDN", ine);
        }

        throw new SmartIdClientException("Error getting serialNumber from certificate subjectDN");
    }

    public static String parseAccount(X509Certificate sidCert) throws CertificateParsingException {
        var sanEntries = sidCert.getSubjectAlternativeNames();

        // [[4, CN=PNOEE-30303039914-MOCK-Q]]
        log.debug("san {}", sanEntries);

        String sidAccountNum = null;
        if (sanEntries != null) {
            for (List<?> sanEntry : sanEntries) {
                Integer sanType = (Integer) sanEntry.get(0);
                Object sanValue = sanEntry.get(1);

                //4 - directoryName
                if (sanType == 4 && sanValue instanceof String sanValueStr) {

                    Pattern cnPattern = Pattern.compile("CN=([A-Za-z0-9-]+)");
                    Matcher cnMatcher = cnPattern.matcher(sanValueStr);

                    if (cnMatcher.find()) {
                        sidAccountNum = cnMatcher.group(1);
                        log.debug("sid account number: {}", sidAccountNum);
                    }
                }
            }
        }

        return sidAccountNum;
    }

    /**
     * Return RSA public in PEM PKCS#1 format, useful for validating signatures in JWT tools like https://sdjwt.org/
     * <pre>
     *   -----BEGIN RSA PUBLIC KEY-----
     *   MIID...AE=
     *   -----END RSA PUBLIC KEY-----
     * </pre>
     * @param rsaCertificate certificate containing RSA public key
     * @return RSA public key in PEM PKCS#1 format
     */
    //XXX: probably should be in PemTools, but as it only supports RSA then it can be here as SID cert specific function
    //XXX: move to PemTools, when EC functionality is added
    public static String getRSAPublicKeyPkcs1Pem(X509Certificate rsaCertificate) {
        Objects.requireNonNull(rsaCertificate);

        PublicKey publicKey = rsaCertificate.getPublicKey();
        if (!KeyAlgorithm.Algorithm.RSA.name().equals(publicKey.getAlgorithm())) {
            throw new IllegalArgumentException("cert doesn't contain RSA public key");
        }

        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

        StringWriter stringWriter = new StringWriter();

        // Get ASN.1 encoded byte array for the RSA public key
        byte[] pkcs1Bytes = rsaPublicKey.getEncoded();
        log.debug("rsa pub key format {}", rsaPublicKey.getFormat());

        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            PemObject pemObject = new PemObject("RSA PUBLIC KEY", pkcs1Bytes);
            pemWriter.writeObject(pemObject);
        } catch (IOException ioException) {
            //StringWriter should never throw IOException
            throw new RuntimeException("Unexpected IOException ", ioException);
        }

        // Return the PEM formatted key
        return stringWriter.toString();
    }

    public String getSemanticsIdentifier() {
        return semanticsIdentifier;
    }

    public void setSemanticsIdentifier(String semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
    }

    @Override
    public String getGivenName() {
        return authIdentity.getGivenName();
    }

    @Override
    public void setGivenName(String givenName) {
        authIdentity.setGivenName(givenName);
    }

    @Override
    public String getSurname() {
        return authIdentity.getSurname();
    }

    @Override
    public void setSurname(String surname) {
        authIdentity.setSurname(surname);
    }

    @Override
    public String getIdentityNumber() {
        return authIdentity.getIdentityNumber();
    }

    @Override
    public void setIdentityNumber(String identityNumber) {
        authIdentity.setIdentityNumber(identityNumber);
    }

    @Override
    public String getIdentityCode() {
        return authIdentity.getIdentityCode();
    }

    @Override
    public void setIdentityCode(String identityCode) {
        authIdentity.setIdentityCode(identityCode);
    }

    @Override
    public String getCountry() {
        return authIdentity.getCountry();
    }

    @Override
    public void setCountry(String country) {
        authIdentity.setCountry(country);
    }

    @Override
    public X509Certificate getAuthCertificate() {
        return authIdentity.getAuthCertificate();
    }

    @Override
    public Optional<LocalDate> getDateOfBirth() {
        return authIdentity.getDateOfBirth();
    }

    @Override
    public void setDateOfBirth(LocalDate dateOfBirth) {
        authIdentity.setDateOfBirth(dateOfBirth);
    }
}
