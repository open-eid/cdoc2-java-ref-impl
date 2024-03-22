package ee.cyber.cdoc20;

import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.keymaterial.DecryptionKeyMaterial;

import org.apache.commons.compress.archivers.ArchiveEntry;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.List;


/**
 * CDOC2 container decryption data builder.
 */
public class CDocDecrypter {

    private DecryptionKeyMaterial recipientKeyMaterial;
    private InputStream cDocInputStream;
    private File destinationDirectory;
    private File cDocFile;
    private List<String> filesToExtract;
    private KeyCapsuleClientFactory keyServerClientFactory;

    @SuppressWarnings("checkstyle:HiddenField")
    public CDocDecrypter withRecipient(KeyPair recipientKeyPair) {
        this.recipientKeyMaterial = DecryptionKeyMaterial.fromKeyPair(recipientKeyPair);
        return this;
    }

    public CDocDecrypter withRecipient(DecryptionKeyMaterial decryptionKeyMaterial) {
        this.recipientKeyMaterial = decryptionKeyMaterial;
        return this;
    }

    @SuppressWarnings("checkstyle:HiddenField")
    public CDocDecrypter withCDoc(File cDocFile) throws FileNotFoundException {
        this.cDocFile = cDocFile;
        this.cDocInputStream = new FileInputStream(cDocFile);
        return this;
    }

    @SuppressWarnings("checkstyle:HiddenField")
    public CDocDecrypter withDestinationDirectory(File destinationDirectory) {
        this.destinationDirectory = destinationDirectory;
        return this;
    }

    @SuppressWarnings("checkstyle:HiddenField")
    public CDocDecrypter withFilesToExtract(List<String> filesToExtract) {
        this.filesToExtract = filesToExtract;
        return this;
    }

    public CDocDecrypter withKeyServers(KeyCapsuleClientFactory clientFactory) {
        this.keyServerClientFactory = clientFactory;
        return this;
    }

    public List<String> decrypt() throws IOException, CDocException, CDocValidationException {
        validate(true);

        try {
            if ((filesToExtract == null) || (filesToExtract.isEmpty())) {
                return Envelope.decrypt(cDocInputStream, recipientKeyMaterial, destinationDirectory.toPath(),
                        keyServerClientFactory);
            } else {
                return Envelope.decrypt(cDocInputStream, recipientKeyMaterial, destinationDirectory.toPath(),
                        filesToExtract, keyServerClientFactory);
            }
        } catch (GeneralSecurityException | CDocParseException ex) {
            throw logDecryptionErrorAndThrow(ex);
        }
    }

    /**
     * List file names in CDoc.
     * @return List of files in cDocFile
     */
    public List<ArchiveEntry> list() throws IOException, CDocException, CDocValidationException {
        validate(false);
        try {
            return Envelope.list(cDocInputStream, recipientKeyMaterial, keyServerClientFactory);
        } catch (GeneralSecurityException | CDocParseException ex) {
            throw logDecryptionErrorAndThrow(ex);
        }
    }

    public void validate(boolean extract) throws CDocValidationException {
        if (cDocFile == null) {
            throw new CDocValidationException("Must provide CDOC input file");
        }

        if (extract && (destinationDirectory == null)) {
            throw new CDocValidationException("Must provide CDOC destination directory");
        }

        if (extract && (!destinationDirectory.exists()
                || !destinationDirectory.isDirectory()
                || !destinationDirectory.canWrite())) {
            throw new CDocValidationException("Destination directory " + destinationDirectory + " is not writable");
        }

        if (recipientKeyMaterial == null) {
            throw new CDocValidationException("Must provide decryption key material");
        }
    }

    private CDocException logDecryptionErrorAndThrow(Exception ex) {
        String fileName = (cDocFile != null) ? cDocFile.getAbsolutePath() : "";
        return new CDocException("Error decrypting " + fileName, ex);
    }

}
