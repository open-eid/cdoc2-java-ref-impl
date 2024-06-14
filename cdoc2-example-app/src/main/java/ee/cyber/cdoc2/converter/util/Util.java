package ee.cyber.cdoc2.converter.util;

import ee.cyber.cdoc2.CDocBuilder;
import ee.cyber.cdoc2.CDocException;
import ee.cyber.cdoc2.CDocValidationException;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;

import org.openeid.cdoc4j.CDOCDecrypter;
import org.openeid.cdoc4j.exception.CDOCException;
import org.openeid.cdoc4j.token.Token;
import org.openeid.cdoc4j.token.pkcs12.PKCS12Token;
import org.openeid.cdoc4j.token.pkcs12.exception.PKCS12Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class Util {

    static final int LABEL_LEN_BYTES = 64/8;
    private static final Logger log = LoggerFactory.getLogger(Util.class);

    public static final String PROMPT = "Enter password for re-encryption: ";

    public static final String PROMPT_RENTER = "Re-enter password for re-encryption: ";

    public static final String PW_DONT_MATCH = "Passwords don't match";

    /**
     * Ask password interactively. If System.console() is available then password is read using
     * console. Otherwise, password is asked using GUI prompt.
     * @param prompt Prompt text to ask
     * @return password entered by user
     */
    public static char[] readPasswordInteractively(String prompt) {

        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        } else { //running from IDE, console is null

            JPasswordField pf = new JPasswordField();
            int result = JOptionPane.showConfirmDialog(null, pf, prompt,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (result == JOptionPane.OK_OPTION) {
                return pf.getPassword();
            } else if (result == JOptionPane.OK_CANCEL_OPTION) {
                throw new RuntimeException("Password entry cancelled by user");
            } else {
                throw new RuntimeException("Password not entered");
            }
        }
    }

    /**
     * Re-Encrypt cdoc format InputStream into cdoc2 format OutputStream
     * @param cdoc cdoc inputStream to re-encrypt into cdoc2 format
     * @param cdocToken cdoc4j token used for decrypting
     * @param password password used for encryption
     * @param tempDir Extract cdoc files under tempDir or in the OS temporary directory if dir is null
     */
    public static void reEncrypt(InputStream cdoc, Token cdocToken,
                                 File cdoc2OutFile, String label, char[] password,
                                 @Nullable Path tempDir) throws CDocException,
        IOException, CDocValidationException, CDOCException {

        Path outDir = (tempDir != null)
            ? Files.createDirectories(tempDir.resolve(UUID.randomUUID().toString()))
            : Files.createTempDirectory(UUID.randomUUID().toString());
        log.debug("Temp outDir {}", outDir);
        outDir.toFile().deleteOnExit();

        // remove temporary unencrypted files
        try (AutoRemovableDir dir = new AutoRemovableDir(outDir)) {
            List<File> dataFiles = new CDOCDecrypter()
                .withToken(cdocToken)
                .withCDOC(cdoc)
                .decrypt(outDir.toFile());

            new CDocBuilder()
                .withPayloadFiles(dataFiles)
                .withRecipients(List.of(EncryptionKeyMaterial.fromPassword(password, label)))
                .buildToFile(cdoc2OutFile);
        }
    }

    /**
     *
     * @param p12 p12 file and its password separated by ':'. Example secret.p12:passwd
     * @return cdoc4j.Token
     * @throws IOException
     * @throws PKCS12Exception
     */
    public static Token readPkcs12Token(String p12) throws IOException, PKCS12Exception {
        String[] split = p12.split(":");
        if (split.length < 1 || split.length > 2) {
            throw new IllegalArgumentException("Invalid .p12 file: " + p12);
        }

        String p12FileName = (split.length == 2) ? split[0] : p12;
        String p12Passwd = (split.length == 2) ? split[1] : null;

        // cdoc4j lib PKCS12Token fails with null password, although PKCS12KeyStore can be without password
        return new PKCS12Token(new FileInputStream(p12FileName), p12Passwd);
    }

    /**
     * Generates CDOC2 filename from CDOC filename.
     * @param cdocFile cdoc format fileName
     * @return CDOC2 filename
     */
    public static File genCDoc2Filename(File cdocFile) {
        String cdocName = cdocFile.getName();

        String cdoc2Name = (cdocName.toUpperCase().endsWith("CDOC"))
            ? cdocName + "2" : cdocName + ".cdoc2";

        return cdocFile.toPath().getParent().resolve(cdoc2Name).toFile();
    }

    /**
     * Generate label (label identifies password for user. If not provided, then generate random label)
     * @return
     */
    public static String genPwLabel() throws GeneralSecurityException{
        byte[] salt = new byte[LABEL_LEN_BYTES];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}
