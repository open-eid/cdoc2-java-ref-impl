package ee.cyber.cdoc2.util;

import java.security.cert.CertificateException;
import java.util.List;
import javax.annotation.Nullable;
import javax.naming.NamingException;

import ee.cyber.cdoc2.crypto.KeyLabelTools;


/**
 * Utility class to downloading and parsing certificates from SK LDAP server
 * @see <a href=https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/>SK LDAP</a>
 */
public final class SkLdapUtil extends EstEidLdapUtil {

    private SkLdapUtil() {
    }

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

    /**
     * SK LDAP provider configuration
     */
    private static final LdapProviderConfig SK_CONFIG = new LdapProviderConfig() {
        @Override
        public String getLdapServerUrl() {
            return SK_ESTEID_LDAP;
        }

        @Override
        public String getBaseDn() {
            return "dc=ESTEID,c=EE";
        }

        @Override
        public boolean isValidDistinguishedName(String distinguishedName) {
            return distinguishedName.contains(AUTH_ID_CARD)
                || distinguishedName.contains(AUTH_DIGI_ID)
                || distinguishedName.contains(AUTH_E_RESIDENT_DIGI_ID);
        }

        @Override
        public KeyLabelTools.KeyLabelType getKeyLabelType(@Nullable String distinguishedName) {
            if (distinguishedName != null) {
                if (distinguishedName.contains(DIGI_ID)) {
                    return KeyLabelTools.KeyLabelType.ID_CARD_DIGI_ID;
                } else if (distinguishedName.contains(E_RESIDENT_DIGI_ID)) {
                    return KeyLabelTools.KeyLabelType.ID_CARD_E_RESIDENT;
                } else if (distinguishedName.contains(ID_CARD)) {
                    return KeyLabelTools.KeyLabelType.ID_CARD_DEFAULT;
                }
            }
            return KeyLabelTools.KeyLabelType.ID_CARD_DEFAULT;
        }

        @Override
        public String getKeyLabelSuffix(@Nullable String distinguishedName) {
            if (distinguishedName != null) {
                if (distinguishedName.contains(DIGI_ID)) {
                    return " (digi-id)";
                } else if (distinguishedName.contains(E_RESIDENT_DIGI_ID)) {
                    return " (e-resident digi-id)";
                } else if (distinguishedName.contains(ID_CARD)) {
                    return " (id-card)";
                }
            }
            return "";
        }

        @Override
        public String getProviderName() {
            return "SK";
        }
    };

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
    public static List<CertificateData> getPublicKeysWithLabels(String[] ids)
        throws NamingException, CertificateException {
        return EstEidLdapUtil.getPublicKeysWithLabels(ids, SK_CONFIG);
    }
}
