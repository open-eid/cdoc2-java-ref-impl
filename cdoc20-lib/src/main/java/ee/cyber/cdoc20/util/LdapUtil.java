package ee.cyber.cdoc20.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

public final class LdapUtil {
    private LdapUtil() {

    }
    private static final Logger log = LoggerFactory.getLogger(LdapUtil.class);
    public static final String SK_ESTEID_LDAP = "ldaps://esteid.ldap.sk.ee/";

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
     * @return List of X509Certificates or empty list if none found
     * @throws NamingException If an error occurred while querying sk LDAP server
     * @throws CertificateException If parsing found certificate fails
     * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
     */
    public static List<X509Certificate> findAuthenticationEstEidCertificates(DirContext ctx, String identificationCode)
            throws NamingException, CertificateException {

        List<X509Certificate> certificateList = new LinkedList<>();
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

            if (name.contains("ou=Authentication,o=Digital identity card")
                    || name.contains("ou=Authentication,o=Identity card of Estonian citizen")) {

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
                            certificateList.add(cert);
                        } catch (CertificateException ce) {
                            log.error("Invalid certificate for {}", identificationCode);
                            throw ce;
                        }
                    }
                }
            }
        }

        return certificateList;
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
    public static List<PublicKey> getCertKeys(String[] ids) throws NamingException, CertificateException {
        if (ids == null) {
            return List.of();
        }
        DirContext ctx = initDirContext();
        LinkedList<PublicKey> keys = new LinkedList<>();
        try {
            for (String id : ids) {
                List<X509Certificate> certs = findAuthenticationEstEidCertificates(ctx, id);
                for (X509Certificate cert: certs) {
                    keys.add(cert.getPublicKey());
                    List<String> cn = new LdapName(cert.getSubjectX500Principal().getName()).getRdns().stream()
                            .filter(rdn -> rdn.getType().equalsIgnoreCase("cn"))
                            .map(rdn -> rdn.getValue().toString())
                            .toList();

                    if (cn.size() == 1) {
                        log.info("Certificate for {}", cn.get(0));
                    } else {
                        log.warn("Unexpected certificate cn values {}", cn);
                    }
                }
            }
        } finally {
            ctx.close();
        }

        return keys;
    }
}
