package ee.cyber.cdoc2.util;

import java.io.ByteArrayInputStream;
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
 * Abstract base class for Estonian eID LDAP utilities.
 * Provides common functionality for querying LDAP servers and parsing certificates.
 * Subclasses must implement provider-specific configuration.
 */
public abstract class EstEidLdapUtil {

    private static final Logger log = LoggerFactory.getLogger(EstEidLdapUtil.class);

    /**
     * Configuration interface for LDAP provider-specific settings
     */
    protected interface LdapProviderConfig {
        /**
         * Get the LDAP server URL
         * @return LDAP server URL (e.g., "ldaps://ldap.example.com/")
         */
        String getLdapServerUrl();

        /**
         * Get the base DN for searching
         * @return Base DN (e.g., "dc=ESTEID,c=EE")
         */
        String getBaseDn();

        /**
         * Check if a distinguished name is valid for this provider
         * @param distinguishedName The DN to check
         * @return true if the DN matches this provider's certificate types
         */
        boolean isValidDistinguishedName(String distinguishedName);

        /**
         * Get the key label type for a certificate based on its distinguished name
         * @param distinguishedName The distinguished name (optional)
         * @return KeyLabelType for this certificate
         */
        KeyLabelTools.KeyLabelType getKeyLabelType(@Nullable String distinguishedName);

        /**
         * Get the human-readable label suffix for a certificate type
         * @param distinguishedName The distinguished name
         * @return Label suffix (e.g., " (id-card)") or empty string
         */
        String getKeyLabelSuffix(@Nullable String distinguishedName);

        /**
         * Get the provider name for logging
         * @return Provider name (e.g., "SK", "Zetes")
         */
        String getProviderName();
    }

    /**
     * Initialize JNDI directory context for LDAP connection
     * @param ldapServerUrl LDAP server URL
     * @return DirContext for LDAP operations
     * @throws NamingException If connection fails
     */
    @SuppressWarnings("java:S1149")
    protected static DirContext initDirContext(String ldapServerUrl) throws NamingException {
        Hashtable<String, Object> env = new Hashtable<>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapServerUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        return new InitialDirContext(env);
    }

    /**
     * Find authentication certificates for ESTEID identification code
     * @param ctx DirContext from {@link #initDirContext(String)}
     * @param identificationCode (isikukood) ESTEID identification code, ex 37101010021
     * @param config Provider-specific configuration
     * @return Map of X509Certificate and distinguished name pairs or empty map if none found
     * @throws NamingException If an error occurred while querying LDAP server
     * @throws CertificateException If parsing found certificate fails
     */
    protected static Map<X509Certificate, String> findAuthenticationEstEidCertificates(
        DirContext ctx,
        String identificationCode,
        LdapProviderConfig config
    ) throws NamingException, CertificateException {
        Map<X509Certificate, String> certificateNameMap = new LinkedHashMap<>();

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String filter = "(serialNumber=PNOEE-" + identificationCode + ")";

        NamingEnumeration<SearchResult> answer = ctx.search(config.getBaseDn(), filter, searchControls);

        while (answer.hasMore()) {
            SearchResult searchResult = answer.next();
            Attributes attrs = searchResult.getAttributes();

            // distinguished name
            // e.g: cn=ŽAIKOVSKI\,IGOR\,37101010021,ou=Authentication,o=Identity card of Estonian citizen
            String dn = searchResult.getName();

            if (config.isValidDistinguishedName(dn)) {
                mapCertificates(certificateNameMap, attrs, identificationCode, dn);
            }
        }

        return certificateNameMap;
    }

    /**
     * Map certificate attributes from LDAP to X509Certificate objects
     * @param certificateNameMap Map to populate with certificates
     * @param attrs LDAP attributes containing certificates
     * @param identificationCode The identification code being searched
     * @param distinguishedName The DN of the LDAP entry
     * @throws CertificateException If certificate parsing fails
     * @throws NamingException If LDAP attribute access fails
     */
    protected static void mapCertificates(
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
     * Find authentication certificates for each ESTEID identification code and extract public keys
     * @param ids ESTEID identification codes (isikukood)
     * @param config Provider-specific configuration
     * @return list of certificate data with parameters parsed from certificates
     * @throws NamingException If an error occurred while querying LDAP server
     * @throws CertificateException If parsing found certificate fails
     */
    protected static List<CertificateData> getPublicKeysWithLabels(
        String[] ids,
        LdapProviderConfig config
    ) throws NamingException, CertificateException {

        if (ids == null) {
            return Collections.emptyList();
        }

        DirContext ctx = initDirContext(config.getLdapServerUrl());

        List<CertificateData> certDatas = new ArrayList<>();
        try {
            for (String id: ids) {
                Map<X509Certificate, String> certs = findAuthenticationEstEidCertificates(ctx, id, config);
                if (certs.isEmpty()) {
                    log.debug(
                        "Identity code {} is not found at {} server", id, config.getProviderName()
                    );
                    continue;
                }

                for (var certNameEntry: certs.entrySet()) {
                    X509Certificate cert = certNameEntry.getKey();
                    String distinguishedName = certNameEntry.getValue();
                    CertificateData certificateData = getKeyLabel(cert, distinguishedName, config);
                    certificateData.setPublicKey(cert.getPublicKey());
                    certificateData.setSerialNumber(getSemanticsIdentifier(cert));

                    log.debug("Adding certificate data from {}: {}", config.getProviderName(), certificateData);
                    certDatas.add(certificateData);
                }
            }
        } finally {
            ctx.close();
        }

        return certDatas;
    }

    /**
     * Prepare key label data from certificate. Used as KeyLabel value in FBS header.
     * For Estonian eID certificates, use CN part of Subject as label, for other certs use x509 Subject.
     * @param cert certificate to be used for label creation
     * @return label parsed from cert
     */
    public static CertificateData getKeyLabel(X509Certificate cert) {
        return getKeyLabel(cert, null, null);
    }

    /**
     * Prepare key label data from certificate. Used as KeyLabel value in FBS header.
     * For Estonian eID certificates, use CN part of Subject as label, for other certs use x509 Subject.
     * @param cert certificate to be used for label creation
     * @param config Provider configuration
     * @return label parsed from cert
     */
    protected static CertificateData getKeyLabel(
        X509Certificate cert,
        @Nullable LdapProviderConfig config
    ) {
        return getKeyLabel(cert, null, config);
    }

    /**
     * Prepare key label data from certificate. Used as KeyLabel value in FBS header.
     * For Estonian eID certificates, use CN part of Subject as label, for other certs use x509 Subject.
     * @param cert certificate to be used for label creation
     * @param dName the distinguished name (optional) - used to add certificate type to the label
     * @param config Provider configuration (optional) - use to add provider specific keyLabel and
     *               keyLabelType to the certificateData. If parameter {@code dName} is present,
     *               then the Provider configuration must be provided.
     * @return label parsed from cert
     */
    protected static CertificateData getKeyLabel(
        X509Certificate cert,
        @Nullable String dName,
        @Nullable LdapProviderConfig config
    ) {
        if (dName != null && config == null) {
            throw new IllegalStateException(
                "If the dName param is present, the LdapProviderConfig must be provided"
            );
        }
        CertificateData certificateData = new CertificateData();

        // Estonian eID certificates have following Subject:
        // Subject: C = EE, CN = "SURNAME,FIRSTNAME,CODE",
        //        SN = SURNAME, GN = FIRSTNAME, serialNumber = PNOEE-CODE
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
                    keyLabel += config.getKeyLabelSuffix(dName);
                    certificateData.setKeyLabelType(config.getKeyLabelType(dName).getName());
                }
                certificateData.setKeyLabel(keyLabel);
            } else {
                log.warn("Unexpected certificate cn values {}", cn);
                certificateData.setKeyLabel(cert.getSubjectX500Principal().getName());
                certificateData.setKeyLabelType(
                    KeyLabelTools.KeyLabelType.ID_CARD_DEFAULT.getName()
                );
            }
            return certificateData;

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
     * (example
     *      subjectDN='serialNumber=PNOEE-38001085718,
     *      givenName=JAAK-KRISTJAN, surname=JÕEORG,
     *      CN="JÕEORG,JAAK-KRISTJAN,38001085718", C=EE'
     * )
     * @param cert certificate
     * @return semanticsIdentifier as String (for example PNOEE-38001085718)
     */
    @Nullable
    protected static String getSemanticsIdentifier(X509Certificate cert) {
        String subjectDN = getSubjectDN(cert);

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

    private static String getSubjectDN(X509Certificate cert) {
        X500Principal subjectX500Principal = cert.getSubjectX500Principal();
        var knownOids = Map.of(
            "2.5.4.5", "serialNumber",
            "2.5.4.42", "givenName",
            "2.5.4.4", "surname");

        // X500Principal in Java 17 doesn't know about knowOids, although deprecated getSubjectDN is able to parse those
        // subjectDN='SERIALNUMBER=PNOEE-30303039914, GIVENNAME=OK, SURNAME=TESTNUMBER, CN="TESTNUMBER,OK", C=EE'
        return subjectX500Principal.getName(X500Principal.RFC2253, knownOids);
    }

    /**
     * Certificate data structure containing certificate information
     */
    public static class CertificateData {
        private java.security.PublicKey publicKey;
        private String keyLabel;
        @Nullable
        private java.io.File file;
        @Nullable
        private String fingerprint;
        @Nullable
        private String serialNumber;
        private String keyLabelType;

        public CertificateData() {
            // utility class
        }

        public java.security.PublicKey getPublicKey() {
            return this.publicKey;
        }

        public String getKeyLabel() {
            return this.keyLabel;
        }

        @Nullable
        public java.io.File getFile() {
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

        public void setPublicKey(java.security.PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public void setKeyLabel(String keyLabel) {
            this.keyLabel = keyLabel;
        }

        public void setFile(@Nullable java.io.File file) {
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

        @Override
        public String toString() {
            return "CertificateData{"
                + "keyLabel='" + keyLabel + '\''
                + ", keyLabelType='" + keyLabelType + '\''
                + ", serialNumber='" + serialNumber + '\''
                + '}';
        }
    }
}
