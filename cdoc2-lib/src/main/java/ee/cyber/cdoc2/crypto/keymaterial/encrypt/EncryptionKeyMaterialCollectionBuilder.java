package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import ee.cyber.cdoc2.util.SkLdapUtil;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;

import java.nio.file.Files;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.createCertKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createPublicKeyLabelParams;


/**
 * Class for creating collection of EncryptionKeyMaterial from multiple sources.
 */
public class EncryptionKeyMaterialCollectionBuilder {

    private final List<EncryptionKeyMaterial> recipients = new LinkedList<>();

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
    public EncryptionKeyMaterialCollectionBuilder fromX509Certificate(
        File[] certificates
    ) throws IOException, CertificateException {

        List<SkLdapUtil.CertificateData> certData = PemTools.loadCertKeysWithLabel(certificates);
        List<EncryptionKeyMaterial> keyMaterials = certData.stream()
            .map(entry -> {
                    KeyLabelParams keyLabelParams = createCertKeyLabelParams(
                        entry.getKeyLabel(), entry.getFingerprint(), entry.getFile()
                    );
                    return EncryptionKeyMaterial.fromPublicKey(entry.getPublicKey(), keyLabelParams);
                }
            )
            .toList();

        recipients.addAll(keyMaterials);
        return this;
    }

    /**
     * Create PasswordEncryptionKeyMaterial from password and keyLabel. KeyLabel can be in plain
     * text or as data params.
     * To decrypt CDOC, recipient must have same password that is identified by the same keyLabel.
     * @param labeledPassword labeled password
     * @return EncryptionKeyMaterial object
     */
    public EncryptionKeyMaterialCollectionBuilder fromPassword(@Nullable LabeledPassword labeledPassword) {
        if (labeledPassword != null) {
            recipients.add(EncryptionKeyMaterial.fromPassword(labeledPassword.getPassword(),
                labeledPassword.getLabel()));
        }
        return this;
    }

    /**
     * Create EncryptionKeyMaterial from label and secret.
     * @param secrets the array of labeled secrets
     * @return the list of EncryptionKeyMaterial
     */
    public EncryptionKeyMaterialCollectionBuilder fromSecrets(@Nullable LabeledSecret[] secrets) {
        if (secrets != null) {
            Arrays.stream(secrets)
                .map(labeledSecret ->
                    EncryptionKeyMaterial.fromSecret(
                        labeledSecret.getSecretKey(),
                        labeledSecret.getLabel()
                    )
                )
                .forEach(recipients::add);
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
