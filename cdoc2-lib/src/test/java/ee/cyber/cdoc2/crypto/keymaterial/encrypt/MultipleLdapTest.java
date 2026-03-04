package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.NamingException;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.util.EstEidLdapUtil;
import ee.cyber.cdoc2.util.SkLdapUtil;
import ee.cyber.cdoc2.util.ZetesLdapUtil;

import static org.junit.jupiter.api.Assertions.*;

public class MultipleLdapTest {

    @Test
    @Tag("ldap")
    @Tag("net")
    void shouldFailIfMissingFromBothLdaps() {
        // Non existent ID code
        String[] ids = new String[]{"30000000000"};
        assertThrows(CertificateException.class, () -> EstEncKeyMaterialBuilder.getCertData(ids));
    }

    @Test
    @Tag("ldap")
    @Tag("net")
    @Disabled("Requires real ID code. As 38001085718 code is for test person - its certificate"
        + " is not available from SK LDAP. Needs to be run separately from other LDAP tests"
        + " with own ID code")
    void testFindsRecipientsFromMultipleLdaps() throws NamingException, CertificateException {
        String skLdapId = "38001085718";
        String zetesLdapId = "38001085718";
        String[] ids = new String[]{skLdapId, zetesLdapId};
        List<EstEidLdapUtil.CertificateData> keysWithLabels =
            EstEncKeyMaterialBuilder.getCertData(
                ids,
                SkLdapUtil::getPublicKeysWithLabels,
                ZetesLdapUtil::getPublicKeysWithLabelsFromTestServer
            );

        assertKeyLabelsValid(keysWithLabels);
        assertEquals(2, keysWithLabels.size());
    }

    @Test
    @Tag("ldap")
    @Tag("net")
    @Disabled("Requires real ID code. As 38001085718 code is for test person - its certificate"
        + " is not available from SK LDAP. Needs to be run separately from other LDAP tests"
        + " with own ID code")
    void testShouldSucceedIfInSkLdap() throws NamingException, CertificateException {
        String skLdapId = "38001085718";
        String[] ids = new String[]{skLdapId};
        List<EstEidLdapUtil.CertificateData> keysWithLabels =
            EstEncKeyMaterialBuilder.getCertData(
                ids,
                SkLdapUtil::getPublicKeysWithLabels,
                ZetesLdapUtil::getPublicKeysWithLabelsFromTestServer
            );

        assertKeyLabelsValid(keysWithLabels);
        assertEquals(1, keysWithLabels.size());
    }

    @Test
    @Tag("ldap")
    @Tag("net")
    void testShouldSucceedIfInZetesLdap() throws NamingException, CertificateException {
        String skLdapId = "38001085718";
        String[] ids = new String[]{skLdapId};
        List<EstEidLdapUtil.CertificateData> keysWithLabels =
            EstEncKeyMaterialBuilder.getCertData(
                ids,
                SkLdapUtil::getPublicKeysWithLabels,
                ZetesLdapUtil::getPublicKeysWithLabelsFromTestServer
            );

        assertKeyLabelsValid(keysWithLabels);
        assertEquals(1, keysWithLabels.size());
    }

    @Test
    @Tag("ldap")
    @Tag("net")
    void shouldFailIfOneIdCodeCannotBeFound() {
        // Non existent ID code
        String skLdapId = "30000000000";
        String zetesLdapId = "38001085718";
        String[] ids = new String[]{skLdapId, zetesLdapId};
        assertThrows(CertificateException.class, () -> EstEncKeyMaterialBuilder.getCertData(ids));
    }

    private static void assertKeyLabelsValid(
        List<EstEidLdapUtil.CertificateData> keysWithLabels
    ) {
        // Since testing against external service, then can't be really sure what is returned
        // if something is returned then consider it success
        assertFalse(keysWithLabels.isEmpty());

        Map<PublicKey, String> ecKeysWithLabels = keysWithLabels.stream()
            .filter(entry -> ECKeys.isSupported(entry.getPublicKey()))
            .collect(Collectors.toMap(
                EstEidLdapUtil.CertificateData::getPublicKey,
                EstEidLdapUtil.CertificateData::getKeyLabel
            ));

        // all returned keys were supported by cdoc
        assertEquals(keysWithLabels.size(), ecKeysWithLabels.size());
    }
}
