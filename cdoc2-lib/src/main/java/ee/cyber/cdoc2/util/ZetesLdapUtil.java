package ee.cyber.cdoc2.util;

import java.security.cert.CertificateException;
import java.util.List;
import javax.annotation.Nullable;
import javax.naming.NamingException;
import ee.cyber.cdoc2.crypto.KeyLabelTools;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.KeyLabelType.ID_CARD_DEFAULT;


/**
 * Utility class for downloading and parsing certificates from Zetes LDAP server
 * Used for Thales-manufactured Estonian ID cards
 * @see <a href="https://repository.eidpki.ee/">Zetes Repository</a>
 * @see <a href="https://www.id.ee/en/article/thales-id-card/">Thales ID Card Information</a>
 */
public final class ZetesLdapUtil extends EstEidLdapUtil {

    private ZetesLdapUtil() {
    }

    // Production LDAP server
    private static final String ZETES_ESTEID_LDAP = "ldaps://ldap.eidpki.ee/";

    // Test LDAP server
    private static final String ZETES_ESTEID_LDAP_TEST = "ldaps://ldap-test.eidpki.ee/";

    private static final String ID_CARD = "IdentityCardEstonianCitizen";
    private static final String AUTH_CERT_PART = "ou=Authentication,o=";

    // distinguished name fragment for authentication certificates using id-card
    private static final String AUTH_ID_CARD = AUTH_CERT_PART + ID_CARD;

    /**
     * Zetes LDAP provider configuration (production)
     */
    private static final LdapProviderConfig ZETES_CONFIG = new LdapProviderConfig() {
        @Override
        public String getLdapServerUrl() {
            return ZETES_ESTEID_LDAP;
        }

        @Override
        public String getBaseDn() {
            return "dc=ESTEID,c=EE,dc=eidpki,dc=ee";
        }

        @Override
        public boolean isValidDistinguishedName(String distinguishedName) {
            return distinguishedName.contains(AUTH_ID_CARD);
        }

        @Override
        public KeyLabelTools.KeyLabelType getKeyLabelType(@Nullable String distinguishedName) {
            return ID_CARD_DEFAULT;
        }

        @Override
        public String getKeyLabelSuffix(@Nullable String distinguishedName) {
            if (distinguishedName != null && distinguishedName.contains(ID_CARD)) {
                return " (id-card)";
            }
            return "";
        }

        @Override
        public String getProviderName() {
            return "Zetes";
        }
    };

    /**
     * Zetes LDAP provider configuration (test server)
     */
    private static final LdapProviderConfig ZETES_TEST_CONFIG = new LdapProviderConfig() {
        @Override
        public String getLdapServerUrl() {
            return ZETES_ESTEID_LDAP_TEST;
        }

        @Override
        public String getBaseDn() {
            return "dc=ESTEID,c=EE,dc=eidpki,dc=ee";
        }

        @Override
        public boolean isValidDistinguishedName(String distinguishedName) {
            return distinguishedName.contains(AUTH_ID_CARD);
        }

        @Override
        public KeyLabelTools.KeyLabelType getKeyLabelType(@Nullable String distinguishedName) {
            return ID_CARD_DEFAULT;
        }

        @Override
        public String getKeyLabelSuffix(@Nullable String distinguishedName) {
            if (distinguishedName != null && distinguishedName.contains(ID_CARD)) {
                return " (id-card)";
            }
            return "";
        }

        @Override
        public String getProviderName() {
            return "Zetes (Test)";
        }
    };

    /**
     * Find Thales ID-card (o=Thales ID-card) authentication (ou=Authentication) certificate
     * for each ESTEID identification code from Zetes ESTEID LDAP and extract public keys
     * @param ids ESTEID identification codes (isikukood), e.g 38001085718
     * @return list of certificate data with few parameters parsed from certificates
     * @throws NamingException If an error occurred while querying Zetes LDAP server
     * @throws CertificateException If parsing found certificate fails
     * @see <a href="https://repository.eidpki.ee/">Zetes Repository</a>
     */
    public static List<CertificateData> getPublicKeysWithLabels(String[] ids)
        throws NamingException, CertificateException {
        return EstEidLdapUtil.getPublicKeysWithLabels(ids, ZETES_CONFIG);
    }

    /**
     * Find Thales ID-card authentication certificates using test LDAP server
     * @param ids ESTEID identification codes (isikukood), e.g 38001085718
     * @return list of certificate data with few parameters parsed from certificates
     * @throws NamingException If an error occurred while querying Zetes LDAP server
     * @throws CertificateException If parsing found certificate fails
     */
    public static List<CertificateData> getPublicKeysWithLabelsFromTestServer(String[] ids)
        throws NamingException, CertificateException {
        return EstEidLdapUtil.getPublicKeysWithLabels(ids, ZETES_TEST_CONFIG);
    }
}
