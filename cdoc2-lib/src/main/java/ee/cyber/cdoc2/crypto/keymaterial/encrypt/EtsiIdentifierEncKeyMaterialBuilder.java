package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.naming.NamingException;

import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.SemanticIdentification;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.util.SkLdapUtil;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.createEIdKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createKeySharesKeyLabelParams;


/**
 * Class for creating collection of EncryptionKeyMaterial for ETSI identifiers.
 */
public class EtsiIdentifierEncKeyMaterialBuilder {

    private final List<EncryptionKeyMaterial> recipients = new LinkedList<>();

    private String[] identificationCodes;

    /**
     * Create EncryptionKeyMaterial, extracted from ETSI identifier.
     * @param idCodes identification codes
     * @return the list of EncryptionKeyMaterial
     */
    public EtsiIdentifierEncKeyMaterialBuilder fromEtsiIdentifier(String[] idCodes) {
        this.identificationCodes = idCodes;
        return this;
    }

    /**
     * Create EncryptionKeyMaterial from publicKey, extracted from identity codes, and keyLabel
     * data params. To decrypt CDOC, recipient must have the private key part of the public key.
     * RSA and EC public keys are supported by CDOC.
     * @param forEId true if encryption is arranging with ID card
     * @return the list of EncryptionKeyMaterial
     */
    public EtsiIdentifierEncKeyMaterialBuilder forEId(boolean forEId)
        throws CertificateException, NamingException {

        if (forEId) {
            List<SkLdapUtil.CertificateData> certData
                = SkLdapUtil.getPublicKeysWithLabels(identificationCodes);
            List<EncryptionKeyMaterial> keyMaterials = certData.stream()
                .filter(entry -> EllipticCurve.isSupported(entry.getPublicKey()))
                .map(cd -> {
                    KeyLabelParams keyLabelParams = createEIdKeyLabelParams(
                        cd.getKeyLabel(), cd.getSerialNumber()
                    );
                    return EncryptionKeyMaterial.fromPublicKey(cd.getPublicKey(), keyLabelParams);
                })
                .toList();

            recipients.addAll(keyMaterials);
        }
        return this;
    }

    /**
     * Create EncryptionKeyMaterial with Smart ID, extracted from ETSI identifier.
     * @param sidCodes natural ID codes
     * @return the list of EncryptionKeyMaterial
     */
    public EtsiIdentifierEncKeyMaterialBuilder forSid(String[] sidCodes) {
        if (null != sidCodes) {
            List<EncryptionKeyMaterial> keyMaterials = Arrays.stream(sidCodes)
                .map(idCode -> {
                    SemanticIdentification semanticIdentifier = SemanticIdentification.forSid(idCode);
                    KeyLabelParams keyLabelParams
                        = createKeySharesKeyLabelParams(semanticIdentifier.getIdentifier());

                    return EncryptionKeyMaterial.fromAuthMeans(semanticIdentifier, keyLabelParams);
                })
                .toList();

            recipients.addAll(keyMaterials);
        }
        return this;
    }

    /**
     * Create EncryptionKeyMaterial with Mobile ID, extracted from ETSI identifier.
     * @param midCodes natural ID codes
     * @return the list of EncryptionKeyMaterial
     */
    public EtsiIdentifierEncKeyMaterialBuilder forMid(String[] midCodes) {
        if (null != midCodes) {
            List<EncryptionKeyMaterial> keyMaterials = Arrays.stream(midCodes)
                .map(idCode -> {
                    // ToDo add mobile number here
                    SemanticIdentification semanticIdentifier = SemanticIdentification.forMid(idCode);
                    KeyLabelParams keyLabelParams
                        = createKeySharesKeyLabelParams(semanticIdentifier.getIdentifier());

                    return EncryptionKeyMaterial.fromAuthMeans(semanticIdentifier, keyLabelParams);
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
