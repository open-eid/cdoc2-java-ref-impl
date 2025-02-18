package ee.cyber.cdoc2.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.crypto.KeyLabelTools;


/**
 * Utility class to downloading and parsing certificates from SK LDAP server
 * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
 */
public final class SkLdapUtil {

    private SkLdapUtil() {
    }

    private static final Logger log = LoggerFactory.getLogger(SkLdapUtil.class);
    private static final String SK_ESTEID_LDAP = "ldaps://esteid.ldap.sk.ee/";

    private static final String DIGI_ID = "Digital identity card";
    private static final String ID_CARD = "Identity card of Estonian citizen";
    private static final String E_RESIDENT_DIGI_ID = "Digital identity card of e-resident";
    private static final String AUTH_CERT_PART = "ou=Authentication,o=";

    // distinguished name fragment for authentication certificates using id-card
    private static final String AUTH_ID_CARD = AUTH_CERT_PART + ID_CARD;

    // distinguished name fragment for authentication certificates using digi-id
    private static final String AUTH_DIGI_ID = AUTH_CERT_PART + DIGI_ID;

    // distinguished name fragment for authentication certificates using e-resident digi-id
    private static final String AUTH_E_RESIDENT_DIGI_ID = AUTH_CERT_PART + E_RESIDENT_DIGI_ID;

    @SuppressWarnings("java:S1149")
    private static DirContext initDirContext() throws NamingException {
        Hashtable<String, Object> env = new Hashtable<>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, SK_ESTEID_LDAP);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        return new InitialDirContext(env);
    }

    /**
     * Find id-kaart (o=Identity card of Estonian citizen) and digi-id (o=Digital identity card)
     * authentication (ou=Authentication) certificates for ESTEID identification code
     * @param ctx DirContext from {@link #initDirContext()}
     * @param identificationCode (isikukood) ESTEID identification code, ex 37101010021
     * @return Map of X509Certificate and distinguished name pairs or empty map if none found
     * @throws NamingException If an error occurred while querying sk LDAP server
     * @throws CertificateException If parsing found certificate fails
     * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
     */
    public static Map<X509Certificate, String> findAuthenticationEstEidCertificates(
        DirContext ctx,
        String identificationCode
    ) throws NamingException, CertificateException {
        Map<X509Certificate, String> certificateNameMap = new LinkedHashMap<>();

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String filter = "(serialNumber=PNOEE-" + identificationCode + ")";

        NamingEnumeration<SearchResult> answer = ctx.search("dc=ESTEID,c=EE", filter, searchControls);

        while (answer.hasMore()) {
            SearchResult searchResult = answer.next();
            Attributes attrs = searchResult.getAttributes();

            // distinguished name
            // e.g: cn=ŽAIKOVSKI\,IGOR\,37101010021,ou=Authentication,o=Identity card of Estonian citizen
            String dn = searchResult.getName();

            if (dn.contains(AUTH_ID_CARD) || dn.contains(AUTH_DIGI_ID) || dn.contains(AUTH_E_RESIDENT_DIGI_ID)) {
                mapCertificates(certificateNameMap, attrs, identificationCode, dn);
            }
        }

        return certificateNameMap;
    }

    private static void mapCertificates(
        Map<X509Certificate, String> certificateNameMap,
        Attributes attrs,
        String identificationCode,
        String distinguishedName
    ) throws CertificateException, NamingException {
        // there can be more than one 'userCertificate;binary' attribute
        var certAttrs = (NamingEnumeration<Object>) attrs.get("userCertificate;binary").getAll();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        while (certAttrs.hasMore()) {
            Object certObject = certAttrs.nextElement();
            if (certObject != null) {
                byte[] certBuf = (byte[]) certObject;
                try {
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(certBuf));
                    log.debug("Found cert for {}, name:{}", identificationCode, distinguishedName);
                    certificateNameMap.put(cert, distinguishedName);
                } catch (CertificateException ce) {
                    log.error("Invalid certificate for {}", identificationCode);
                    throw ce;
                }
            }
        }
    }

    /**
     * Find id-kaart (o=Identity card of Estonian citizen) and digi-id (o=Digital identity card)
     * authentication (ou=Authentication) certificate for each ESTEID identification code from sk ESTEID LDAP and
     * extract public keys
     * @param ids ESTEID identification codes (isikukood), e.g 37101010021
     * @return list of certificate data with few parameters parsed from certFiles
     * @throws NamingException If an error occurred while querying sk LDAP server
     * @throws CertificateException If parsing found certificate fails
     * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
     */
    public static List<SkLdapUtil.CertificateData> getPublicKeysWithLabels(String[] ids)
            throws NamingException, CertificateException {

        if (ids == null) {
            return Collections.emptyList();
        }
        DirContext ctx = initDirContext();

        List<SkLdapUtil.CertificateData> certDatas = new ArrayList<>();
        try {
            for (String id: ids) {
                Map<X509Certificate, String> certs = findAuthenticationEstEidCertificates(ctx, id);
                if (certs.isEmpty()) {
                    throw new CertificateException("Identity code " + id + " is not found at server");
                }

                for (var certNameEntry: certs.entrySet()) {
                    X509Certificate cert = certNameEntry.getKey();
                    String distinguishedName = certNameEntry.getValue();
                    CertificateData certificateData = getKeyLabel(cert, distinguishedName);
                    certificateData.setPublicKey(cert.getPublicKey());
                    certificateData.setSerialNumber(getSemanticsIdentifier(cert));

                    log.debug("Adding certificate data {}", certificateData);
                    certDatas.add(certificateData);
                }
            }
        } finally {
            ctx.close();
        }

        return certDatas;
    }

    /**
     * Prepare key label data from certificate. Used as KeyLabel value in FBS header. For SK issued
     * certificates, use CN part of Subject as label, for other certs use x509 Subject.
     * @param cert certificate to be used for label creation
     * @return label parsed from cert
     */
    public static CertificateData getKeyLabel(X509Certificate cert) {
        return getKeyLabel(cert, null);
    }

    /**
     * Prepare key label data from certificate. Used as KeyLabel value in FBS header. For SK
     * issued certificates, use CN part of Subject as label, for other certs use x509 Subject.
     * @param cert certificate to be used for label creation
     * @param dName the distinguished name (optional) - used to add certificate type to the label
     * @return label parsed from cert
     */
    private static CertificateData getKeyLabel(X509Certificate cert, @Nullable String dName)  {
        CertificateData certificateData = new SkLdapUtil.CertificateData();
        // KeyLabel is UI specific field, so its value is not specified in the Spec.
        // DigiDoc4-Client uses this field to hint user what type of eID was used for encryption
        // https://github.com
        // /open-eid/DigiDoc4-Client/blob/f4298ad9d2fbb40cffc488bed6cf1d3116dff450/client/SslCertificate.cpp#L302
        // https://github.com/open-eid/DigiDoc4-Client/blob/master/client/dialogs/AddRecipients.cpp#L474

        // cdoc2-lib is not trying to be compatible DigiDoc4-Client as this value is not standardized
        // if compatibility is required then lib client must write its own certificate parsing

        // SK issued id-cards have following Subject:
        // Subject: C = EE, CN = "\C5\BDAIKOVSKI,IGOR,37101010021",
        //        SN = \C5\BDAIKOVSKI, GN = IGOR, serialNumber = 37101010021
        // use CN as label.
        // If it fails, use whole certificate subject
        try {
            List<String> cn = new LdapName(cert.getSubjectX500Principal().getName()).getRdns().stream()
                    .filter(rdn -> rdn.getType().equalsIgnoreCase("cn"))
                    .map(rdn -> rdn.getValue().toString())
                    .toList();
            if (cn.size() == 1) {
                String keyLabel = cn.get(0);
                if (dName != null) {
                    if (dName.contains(DIGI_ID)) {
                        keyLabel += " (digi-id)";
                        certificateData.setKeyLabelType(
                            KeyLabelTools.KeyLabelType.ID_CARD_DIGI_ID.getName()
                        );
                    } else if (dName.contains(ID_CARD)) {
                        keyLabel += " (id-card)";
                        certificateData.setKeyLabelType(
                            KeyLabelTools.KeyLabelType.ID_CARD_DEFAULT.getName()
                        );
                    } else if (dName.contains(E_RESIDENT_DIGI_ID)) {
                        keyLabel += " (e-resident digi-id)";
                        certificateData.setKeyLabelType(
                            KeyLabelTools.KeyLabelType.ID_CARD_E_RESIDENT.getName()
                        );
                    }
                }
                certificateData.setKeyLabel(keyLabel);
                return certificateData;
            } else {
                log.warn("Unexpected certificate cn values {}", cn);
                certificateData.setKeyLabel(cert.getSubjectX500Principal().getName());
                certificateData.setKeyLabelType(
                    KeyLabelTools.KeyLabelType.ID_CARD_DEFAULT.getName()
                );
                return certificateData;
            }
        } catch (InvalidNameException e) {
            certificateData.setKeyLabel(cert.getSubjectX500Principal().getName());
            certificateData.setKeyLabelType(
                KeyLabelTools.KeyLabelType.ID_CARD_DEFAULT.getName()
            );
            return certificateData;
        }
    }

    /**
     * Parse serialNumber from certificate subjectDN serialNumber
     * (example subjectDN='SERIALNUMBER=PNOEE-30303039914, GIVENNAME=OK, SURNAME=TESTNUMBER, CN="TESTNUMBER,OK", C=EE')
     * @param cert certificate
     * @return semanticsIdentifier as String (for example PNOEE-30303039914)
     */
    @Nullable
    private static String getSemanticsIdentifier(X509Certificate cert) {
        X500Principal subjectX500Principal = cert.getSubjectX500Principal();
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
            log.info("serialNumber not found from subjectDN {}", subjectDN);
        } catch (InvalidNameException ine) {
            log.info("Failed to get serialNumber from invalid certificate subjectDN field");
        }
        return null;
    }

    public static class CertificateData {
        private PublicKey publicKey;
        private String keyLabel;
        @Nullable
        private File file;
        @Nullable
        private String fingerprint;
        @Nullable
        private String serialNumber;
        private String keyLabelType;

        public CertificateData() {
            // utility class
        }

        public PublicKey getPublicKey() {
            return this.publicKey;
        }

        public String getKeyLabel() {
            return this.keyLabel;
        }

        @Nullable
        public File getFile() {
            return this.file;
        }

        @Nullable
        public String getFingerprint() {
            return this.fingerprint;
        }

        @Nullable
        public String getSerialNumber() {
            return this.serialNumber;
        }

        public String getKeyLabelType() {
            return this.keyLabelType;
        }

        public void setPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public void setKeyLabel(String keyLabel) {
            this.keyLabel = keyLabel;
        }

        public void setFile(@Nullable File file) {
            this.file = file;
        }

        public void setFingerprint(@Nullable String fingerprint) {
            this.fingerprint = fingerprint;
        }

        public void setSerialNumber(@Nullable String serialNumber) {
            this.serialNumber = serialNumber;
        }

        public void setKeyLabelType(String keyLabelType) {
            this.keyLabelType = keyLabelType;
        }
    }

}
