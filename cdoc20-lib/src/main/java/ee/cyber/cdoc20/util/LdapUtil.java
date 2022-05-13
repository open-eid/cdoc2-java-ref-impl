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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
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


    private static X509Certificate queryESTEIDCert(DirContext ctx, String identificationCode)
            throws NamingException, CertificateException {

        X509Certificate cert = null;
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String filter = "(serialNumber=PNOEE-" + identificationCode + ")";

        NamingEnumeration<SearchResult> answer =
                ctx.search("ou=Authentication,o=Identity card of Estonian citizen,dc=ESTEID,c=EE",
                        filter, searchControls);

        if (answer.hasMore()) {
            Attributes attrs = answer.next().getAttributes();
            byte[] certBuf = (byte[]) attrs.get("userCertificate;binary").get();
            cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBuf));
            log.debug("Found cert for {}", identificationCode);
        }

        if (answer.hasMore()) {
            log.warn("More than one result returned for {}", identificationCode);
        }
        
        return cert;
    }
    

    /**
     * Find user certificate for identificationCode
     * @param identificationCode (isikukood) ESTEID identification code, ex 37101010021
     * @return X509 certificate for id or null if not found
     * @throws NamingException If an error occurred while querying sk LDAP server
     * @throws CertificateException If parsing found certificate fails
     * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
     */
    public static X509Certificate findEstEIDCertificate(String identificationCode)
            throws NamingException, CertificateException {

        X509Certificate cert = null;
        DirContext ctx = initDirContext();

        try {
            cert = queryESTEIDCert(ctx, identificationCode);
        } finally {
            ctx.close();
        }

        return cert;
    }


    public static List<ECPublicKey> getCertKeys(String[] ids) throws NamingException, CertificateException {
        if (ids == null) {
            return List.of();
        }
        DirContext ctx = initDirContext();
        LinkedList<ECPublicKey> keys = new LinkedList<>();
        try {
            for (String id : ids) {
                X509Certificate cert = queryESTEIDCert(ctx, id);
                if (cert != null) {
                    keys.add((ECPublicKey) cert.getPublicKey());
                    List<String> cn = new LdapName(cert.getSubjectX500Principal().getName()).getRdns().stream()
                            .filter(rdn -> rdn.getType().equalsIgnoreCase("cn"))
                            .map(rdn -> rdn.getValue().toString())
                            .toList();

                    if (cn.size() == 1) {
                        log.info("Certificate for {}", cn.get(0));
                    } else {
                        log.warn("Unexpected certificate cn values {}", cn);
                    }
                } else {
                    log.error("Certificate not found for {}", id);
                    throw new CertificateException("Certificate not found for " + id);
                }
            }
        } finally {
            ctx.close();
        }

        return keys;
    }
}
