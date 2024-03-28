package ee.cyber.cdoc2.cli;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Properties;

import ee.cyber.cdoc2.CDocConfiguration;
import ee.cyber.cdoc2.CDocDecrypter;
import ee.cyber.cdoc2.CDocValidationException;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.container.CDocParseException;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.cyber.cdoc2.crypto.Pkcs11Tools;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;

/**
 * Utility class for building {@link CDocDecrypter}.
 */
public final class CDocDecryptionHelper {

    private CDocDecryptionHelper() { }

    public static DecryptionKeyMaterial getDecryptionKeyMaterial(
        File cdocFile,
        String password,
        String secret,
        String p12,
        File privKeyFile,
        Integer slot,
        String keyAlias
    ) throws GeneralSecurityException, IOException, CDocValidationException, CDocParseException {
        DecryptionKeyMaterial decryptionKm =
            SymmetricKeyUtil.extractDecryptionKeyMaterialFromSymmetricKey(
                cdocFile.toPath(), password, secret
            );

        if (decryptionKm == null)  {
            String pkcs11LibPath = System.getProperty(CDocConfiguration.PKCS11_LIBRARY_PROPERTY, null);
            KeyPair keyPair;
            if (p12 != null) {
                keyPair = PemTools.loadKeyPairFromP12File(p12);
            } else {
                keyPair = privKeyFile != null
                    ? PemTools.loadKeyPair(privKeyFile)
                    : Pkcs11Tools.loadFromPKCS11Interactively(pkcs11LibPath, slot, keyAlias);
            }

            decryptionKm = DecryptionKeyMaterial.fromKeyPair(keyPair);
        }

        return decryptionKm;
    }

    public static CDocDecrypter getDecrypterWithFilesExtraction(
        File cdocFile,
        String[] filesToExtract,
        File outputPath,
        DecryptionKeyMaterial decryptionKeyMaterial,
        KeyCapsuleClientFactory keyCapsulesClientFactory
    ) throws IOException {
        return new CDocDecrypter()
            .withCDoc(cdocFile)
            .withRecipient(decryptionKeyMaterial)
            .withFilesToExtract(Arrays.asList(filesToExtract))
            .withKeyServers(keyCapsulesClientFactory)
            .withDestinationDirectory(outputPath);
    }

    public static KeyCapsuleClientFactory getKeyCapsulesClientFactory(
        String keyServerPropertiesFile
    ) throws GeneralSecurityException, IOException {
        Properties p = CDocCommonHelper.getServerProperties(keyServerPropertiesFile);

        return KeyCapsuleClientImpl.createFactory(p);
    }

}
