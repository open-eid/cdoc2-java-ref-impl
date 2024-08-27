package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.util.SkLdapUtil;

import javax.naming.NamingException;
import java.io.File;
import java.io.IOException;

import java.nio.file.Files;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.createCertKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createPublicKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.formatKeyLabel;

/**
 * Class for creating collection of EncryptionKeyMaterial from multiple sources.
 */
public class EncryptionKeyMaterialCollectionBuilder {

    private List<EncryptionKeyMaterial> recipients = new LinkedList<>();

    /**
     * Create EncryptionKeyMaterial from publicKey and keyLabel data params. Add to list of recipients.
     * To decrypt CDOC, recipient must have the private key part of the public key. RSA and EC public keys are
     * supported by CDOC2.
     * @param pubPemFiles files
     * @return the list of EncryptionKeyMaterial
     */
    public EncryptionKeyMaterialCollectionBuilder fromPublicKey(File[] pubPemFiles) throws IOException {
        if (pubPemFiles != null) {
            for (File pubKeyPemFile : pubPemFiles) {
                if (!pubKeyPemFile.canRead()) {
                    throw new IllegalArgumentException("Not readable " + pubKeyPemFile);
                }

                PublicKey pubKey = PemTools.loadPublicKey(Files.readString(pubKeyPemFile.toPath()));
                KeyLabelParams params = createPublicKeyLabelParams(null, pubKeyPemFile);
                recipients.add(EncryptionKeyMaterial.fromPublicKey(pubKey, params));
            }
        }
        return this;
    }

    /**
     * Create EncryptionKeyMaterial from publicKey, extracted from certificate, and keyLabel
     * data params. To decrypt CDOC, recipient must have the private key part of the public key.
     * RSA and EC public keys are supported by CDOC.
     * @param certificates certificates
     * @return the list of EncryptionKeyMaterial
     */
    public EncryptionKeyMaterialCollectionBuilder fromX509Certificate(File[] certificates)
        throws IOException, CertificateException {

        List<SkLdapUtil.CertificateData> certData = PemTools.loadCertKeysWithLabel(certificates);
        List<EncryptionKeyMaterial> keyMaterials = certData.stream()
            .map(entry -> {
                    KeyLabelParams keyLabelParams = createCertKeyLabelParams(
                        entry.getKeyLabel(), entry.getFingerprint(), entry.getFile()
                    );
                    return new PublicKeyEncryptionKeyMaterial(
                        entry.getPublicKey(), formatKeyLabel(keyLabelParams)
                    );
                }
            )
            .collect(Collectors.toList());

        recipients.addAll(keyMaterials);
        return this;
    }

    /**
     * Create EncryptionKeyMaterial from publicKey, extracted from identity codes, and keyLabel
     * data params. To decrypt CDOC, recipient must have the private key part of the public key.
     * RSA and EC public keys are supported by CDOC.
     * @param identificationCodes identification codes
     * @return the list of EncryptionKeyMaterial
     */
    public EncryptionKeyMaterialCollectionBuilder fromEId(String[] identificationCodes)
        throws CertificateException, NamingException {

        List<SkLdapUtil.CertificateData> certData
            = SkLdapUtil.getPublicKeysWithLabels(identificationCodes);
        List<EncryptionKeyMaterial> keyMaterials = certData.stream()
            .filter(entry -> EllipticCurve.isSupported(entry.getPublicKey()))
            .map(SkLdapUtil::toEncryptionKeyMaterial)
            .toList();

        recipients.addAll(keyMaterials);
        return this;
    }

    /**
     * Create PasswordEncryptionKeyMaterial from password and keyLabel. KeyLabel can be in plain
     * text or as data params.
     * To decrypt CDOC, recipient must have same password that is identified by the same keyLabel.
     * @param passwordChars password chars for extracting pre-shared SecretKey
     * @param keyLabel password key label
     * @return EncryptionKeyMaterial object
     */
    public EncryptionKeyMaterialCollectionBuilder fromPassword(char[] passwordChars, String keyLabel) {

        Objects.requireNonNull(passwordChars);
        Objects.requireNonNull(keyLabel);
        recipients.add(EncryptionKeyMaterial.fromPassword(passwordChars, keyLabel));
        return this;
    }

    public EncryptionKeyMaterialCollectionBuilder addAll(Collection<EncryptionKeyMaterial> c) {
        recipients.addAll(c);
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
