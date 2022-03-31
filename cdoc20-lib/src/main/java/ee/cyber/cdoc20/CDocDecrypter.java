package ee.cyber.cdoc20;

import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.Envelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.CipherInputStream;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.List;

public class CDocDecrypter {
    private static final Logger log = LoggerFactory.getLogger(CDocDecrypter.class);


    private KeyPair recipientKeyPair;
    private InputStream cDocInputStream;
    private File destinationDirectory;

    private File cDocFile;

    public CDocDecrypter withRecipient(KeyPair recipientKeyPair) {
        this.recipientKeyPair = recipientKeyPair;
        return this;
    }

    public CDocDecrypter withCDoc(File cDocFile) throws FileNotFoundException {
        this.cDocFile = cDocFile;
        this.cDocInputStream = new FileInputStream(cDocFile);
        return this;
    }

    public CDocDecrypter withDestinationDirectory(File destinationDirectory) {
        this.destinationDirectory = destinationDirectory;
        return this;
    }

    public void decrypt() throws IOException, CDocException{
        //TODO: validate

        try {
            List<String> extractedFileNames =
                    Envelope.decrypt(cDocInputStream, recipientKeyPair, destinationDirectory.toPath());
            System.out.println("Decrypted "+extractedFileNames+" into "+destinationDirectory.getAbsolutePath());
        } catch (GeneralSecurityException | CDocParseException ex) {
            String fileName = (cDocFile != null) ? cDocFile.getAbsolutePath(): "";
            throw new CDocException("Error decrypting "+fileName, ex);
        }
    }

    /**
     * List file names in CDoc.
     * @return List of files in cDocFile
     */
    public List<String> list() {
        //TODO: implement file listing
        return List.of();
    }

}
