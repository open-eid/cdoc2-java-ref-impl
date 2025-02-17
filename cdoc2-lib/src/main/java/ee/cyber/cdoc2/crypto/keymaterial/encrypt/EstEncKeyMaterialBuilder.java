package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.naming.NamingException;

import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.util.SkLdapUtil;

import static ee.cyber.cdoc2.crypto.AuthenticationIdentifier.createSemanticsIdentifier;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createEIdKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createKeySharesKeyLabelParams;


/**
 * Class for creating collection of EncryptionKeyMaterial from Estonian ID codes. Will use SK LDAP to download
 * certificates.
 * This class is Estonian ID and SK ID solutions specific. Use to create EncryptionKeyMaterial from Estonian ID codes or
 * use as an example to download from custom identity/certificate provider.
 *
 * @see <a href="https://et.wikipedia.org/wiki/Isikukood">Isikukood</a>
 */
public class EstEncKeyMaterialBuilder {

    private final List<EncryptionKeyMaterial> recipients = new LinkedList<>();

    /**
     * Download certificate from SK LDAP server and create PublicKeyEncryptionKeyMaterial from it.
     * @param identificationCodes Estonian national personal identifier (isikukood)
     * @return the list of EncryptionKeyMaterial
     */
    public EstEncKeyMaterialBuilder fromCertDirectory(String[] identificationCodes)
        throws CertificateException, NamingException {

        List<SkLdapUtil.CertificateData> certData
            = SkLdapUtil.getPublicKeysWithLabels(identificationCodes);
        List<EncryptionKeyMaterial> keyMaterials = certData.stream()
            .filter(entry -> EllipticCurve.isSupported(entry.getPublicKey()))
            .map(cd -> {
                KeyLabelParams keyLabelParams = createEIdKeyLabelParams(
                    cd.getKeyLabel(), cd.getSerialNumber(), cd.getKeyLabelType()
                );
                return EncryptionKeyMaterial.fromPublicKey(cd.getPublicKey(), keyLabelParams);
            })
            .toList();

        recipients.addAll(keyMaterials);

        return this;
    }

    /**
     * Create EncryptionKeyMaterial with Smart ID, extracted from ETSI identifier.
     * @param sidCodes natural ID codes
     * @return the list of EncryptionKeyMaterial
     */
    public EstEncKeyMaterialBuilder forSid(String[] sidCodes) {
        return withKeyShares(sidCodes, AuthenticationIdentifier.AuthenticationType.SID);
    }

    /**
     * Create EncryptionKeyMaterial with Mobile ID, extracted from ETSI identifier.
     * @param midCodes Estonian natural person ID codes. Example `48010010101`, internally converted to
     *                 SemanticsIdentifier (`PNOEE-48010010101`)
     * @return the list of EncryptionKeyMaterial
     */
    public EstEncKeyMaterialBuilder forMid(String[] midCodes) {
        return withKeyShares(midCodes, AuthenticationIdentifier.AuthenticationType.MID);
    }

    /**
     * Creates KeyShareEncryptionMaterial form Estonian Natural Person identity code (isikukood).
     * @param identityCodes Estonian natural person ID codes. Example `48010010101`, internally converted to
     *                      SemanticsIdentifier (`PNOEE-48010010101`)
     * @return
     */
    public EstEncKeyMaterialBuilder forAuthMeans(String[] identityCodes) {
        return forSid(identityCodes); //there is no difference between MID/SID when encrypting.
    }

    /**
     *
     * @param idCodes Estonian natural ID codes. Example `48010010101`, internally converted to
     *                SemanticsIdentifier (`PNOEE-48010010101`)
     * @param authType
     * @return
     */
    private EstEncKeyMaterialBuilder withKeyShares(
        String[] idCodes, AuthenticationIdentifier.AuthenticationType authType
    ) {
        if (null != idCodes) {
            List<EncryptionKeyMaterial> keyMaterials = Arrays.stream(idCodes)
                .map(idCode -> {
                    SemanticsIdentifier semanticsIdentifier = createSemanticsIdentifier(idCode);
                    AuthenticationIdentifier authIdentifier = AuthenticationIdentifier
                        .forKeyShares(semanticsIdentifier, authType);
                    KeyLabelParams keyLabelParams = createKeySharesKeyLabelParams(
                        authIdentifier.getEtsiIdentifier()
                    );

                    return EncryptionKeyMaterial.fromAuthMeans(authIdentifier, keyLabelParams);
                })
                .toList();

            recipients.addAll(keyMaterials);
        }
        return this;
    }

    /**
     * Create EncryptionKeyMaterial collection from all provided sources
     * @return the list of EncryptionKeyMaterial
     */
    public List<EncryptionKeyMaterial> build() {
        return recipients;
    }

}
