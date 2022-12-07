package ee.cyber.cdoc20;

import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import org.apache.commons.compress.archivers.ArchiveEntry;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.List;

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

    public List<String> decrypt() throws IOException, CDocException {
        //TODO: validate

        try {
            if ((filesToExtract == null) || (filesToExtract.isEmpty())) {
                return Envelope.decrypt(cDocInputStream, recipientKeyMaterial, destinationDirectory.toPath(),
                        keyServerClientFactory);
            } else {
                return Envelope.decrypt(cDocInputStream, recipientKeyMaterial, destinationDirectory.toPath(),
                        filesToExtract, keyServerClientFactory);
            }
        } catch (GeneralSecurityException | CDocParseException ex) {
            String fileName = (cDocFile != null) ? cDocFile.getAbsolutePath() : "";
            throw new CDocException("Error decrypting " + fileName, ex);
        }
    }

    /**
     * List file names in CDoc.
     * @return List of files in cDocFile
     */
    public List<ArchiveEntry> list() throws IOException, CDocException {
        try {
            return Envelope.list(cDocInputStream, recipientKeyMaterial, keyServerClientFactory);
        } catch (GeneralSecurityException | CDocParseException ex) {
            String fileName = (cDocFile != null) ? cDocFile.getAbsolutePath() : "";
            throw new CDocException("Error decrypting " + fileName, ex);
        }
    }

}
