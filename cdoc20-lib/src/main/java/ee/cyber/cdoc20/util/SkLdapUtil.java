package ee.cyber.cdoc20.util;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class to downloading and parsing certificates from SK LDAP server
 * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
 */
public final class SkLdapUtil {
    private SkLdapUtil() {

    }
    private static final Logger log = LoggerFactory.getLogger(SkLdapUtil.class);
    public static final String SK_ESTEID_LDAP = "ldaps://esteid.ldap.sk.ee/";

    public static final String DIGI_ID = "Digital identity card";
    public static final String ID_CARD = "Identity card of Estonian citizen";

    //dir name for certificates meant for authentication with digi-id
    private static final String DIR_NAME_AUTH_DIGI_ID = "ou=Authentication,o=" + DIGI_ID;

    //dir name for certificates meant for authentication with id-card
    private static final String DIR_NAME_AUTH_ID_CARD = "ou=Authentication,o=" + ID_CARD;


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
     * @return Map of X509Certificate and directoryName pairs or empty map if none found
     * @throws NamingException If an error occurred while querying sk LDAP server
     * @throws CertificateException If parsing found certificate fails
     * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
     */
    public static Map<X509Certificate, String> findAuthenticationEstEidCertificates(DirContext ctx,
                                                                                    String identificationCode)
            throws NamingException, CertificateException {

        Map<X509Certificate, String> certificateNameMap = new LinkedHashMap<>();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String filter = "(serialNumber=PNOEE-" + identificationCode + ")";

        NamingEnumeration<SearchResult> answer =
                ctx.search("dc=ESTEID,c=EE",
                        filter, searchControls);

        while (answer.hasMore()) {
            SearchResult searchResult = answer.next();
            Attributes attrs = searchResult.getAttributes();

            // directory name
            // ex cn=ŽAIKOVSKI\,IGOR\,37101010021,ou=Authentication,o=Identity card of Estonian citizen
            String name = searchResult.getName();

            if (name.contains(DIR_NAME_AUTH_ID_CARD)
                    || name.contains(DIR_NAME_AUTH_DIGI_ID)) {

                // there can be more than one 'userCertificate;binary' attribute
                NamingEnumeration<Object> certAttrs =
                        (NamingEnumeration<Object>) attrs.get("userCertificate;binary").getAll();
                while (certAttrs.hasMore()) {
                    Object certObject = certAttrs.nextElement();
                    if (certObject != null) {
                        byte[] certBuf = (byte[]) certObject;
                        try {
                            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                                    new ByteArrayInputStream(certBuf));
                            log.debug("Found cert for {}, name:{}", identificationCode, name);
                            certificateNameMap.put(cert, name);
                        } catch (CertificateException ce) {
                            log.error("Invalid certificate for {}", identificationCode);
                            throw ce;
                        }
                    }
                }
            }
        }

        return certificateNameMap;
    }

    /**
     * Find id-kaart (o=Identity card of Estonian citizen) and digi-id (o=Digital identity card)
     * authentication (ou=Authentication) certificate for each ESTEID identification code from sk ESTEID LDAP and
     * extract public keys
     * @param ids ESTEID identification codes (isikukood), ex 37101010021
     * @return List of public keys for each identification code or empty list if none found
     * @throws NamingException If an error occurred while querying sk LDAP server
     * @throws CertificateException If parsing found certificate fails
     * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
     */
    public static Map<PublicKey, String> getCertKeysWithLabels(String[] ids)
            throws NamingException, CertificateException {

        if (ids == null) {
            return Map.of();
        }
        DirContext ctx = initDirContext();
        Map<PublicKey, String> keysWithLabels = new LinkedHashMap<>();
        try {
            for (String id : ids) {
                Map<X509Certificate, String> certs = findAuthenticationEstEidCertificates(ctx, id);
                for (var certNameEntry: certs.entrySet()) {
                    X509Certificate cert = certNameEntry.getKey();
                    String dirName = certNameEntry.getValue();
                    String keyLabel = getKeyLabel(cert, dirName);
                    log.debug("Adding key label {}", keyLabel);
                    keysWithLabels.put(cert.getPublicKey(), keyLabel);
                }
            }
        } finally {
            ctx.close();
        }

        return keysWithLabels;
    }

    /**
     * Get label value from certificate. Used as KeyLabel value in FBS header. For SK issued certificates,
     * use CN part of Subject as label, for other certs use x509 Subject
     * @param cert certificate to be used for label creation
     * @return label parsed from cert
     */
    public static String getKeyLabel(X509Certificate cert) {
        return getKeyLabel(cert, null);
    }

    /**
     * Get label value from certificate. Used as KeyLabel value in FBS header. For SK issued certificates,
     * use CN part of Subject as label, for other certs use x509 Subject
     * @param cert certificate to be used for label creation
     * @param dirName optional directory name of certificate. If not present then value is null.
     * @return label parsed from cert
     */
    private static String getKeyLabel(X509Certificate cert, @Nullable String dirName)  {
        // KeyLabel is UI specific field, so its value is not specified in the Spec.
        // DigiDoc4-Client uses this field to hint user what type of eID was used for encryption
        // https://github.com
        // /open-eid/DigiDoc4-Client/blob/f4298ad9d2fbb40cffc488bed6cf1d3116dff450/client/SslCertificate.cpp#L302
        // https://github.com/open-eid/DigiDoc4-Client/blob/master/client/dialogs/AddRecipients.cpp#L474

        // cdoc20-lib is not trying to be compatible DigiDoc4-Client as this value is not standardized
        // if compatibility is required then lib client must write its own certificate parsing


        // SK issued id-cards have following Subject:
        // Subject: C = EE, O = ESTEID, OU = authentication, CN = "\C5\BDAIKOVSKI,IGOR,37101010021",
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
                if (dirName != null) {
                    if (dirName.contains(DIGI_ID)) {
                        keyLabel += " (digi-id)";
                    }

                    if (dirName.contains(ID_CARD)) {
                        keyLabel += " (id-card)";
                    }
                }
                return keyLabel;
            } else {
                log.warn("Unexpected certificate cn values {}", cn);
                return cert.getSubjectX500Principal().getName();
            }
        } catch (InvalidNameException e) {
            return cert.getSubjectX500Principal().getName();
        }
    }
}
