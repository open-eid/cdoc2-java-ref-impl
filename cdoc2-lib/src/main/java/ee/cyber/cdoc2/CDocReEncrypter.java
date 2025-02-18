package ee.cyber.cdoc2;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Objects;

import javax.annotation.Nullable;

import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.exceptions.CDocException;

import ee.cyber.cdoc2.services.Services;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * CDOC2 container re-encryption data builder.
 */
public class CDocReEncrypter {

    private static final Logger log = LoggerFactory.getLogger(CDocReEncrypter.class);
    private final File cDocFile;

    private final DecryptionKeyMaterial decryptionKeyMaterial;

    private final File destCdocFile;

    private final EncryptionKeyMaterial reEncryptionKeyMaterial;

    @Nullable
    private Services services;

    public CDocReEncrypter(
        File cDocFile,
        DecryptionKeyMaterial decryptionKeyMaterial,
        File destCdocFile,
        EncryptionKeyMaterial reEncryptionKeyMaterial,
        @Nullable Services services
    ) {
        Objects.nonNull(cDocFile);
        Objects.nonNull(decryptionKeyMaterial);
        Objects.nonNull(destCdocFile);
        Objects.nonNull(reEncryptionKeyMaterial);

        this.cDocFile = cDocFile;
        this.decryptionKeyMaterial = decryptionKeyMaterial;
        this.destCdocFile = destCdocFile;
        this.reEncryptionKeyMaterial = reEncryptionKeyMaterial;
        this.services = services;
    }

//    public void addKeyShareClientFactory(ExternalService keyShareClientFactory) {
//        serverClientFactory = keyShareClientFactory;
//    }

    public void reEncryptCDocContainer()
        throws IOException, CDocException, GeneralSecurityException {

        log.info("Re-encrypting {} as {}", cDocFile, destCdocFile);

        Path destDir = this.destCdocFile.toPath().toAbsolutePath().getParent();

        try (InputStream inCdocIs = Files.newInputStream(this.cDocFile.toPath());
             OutputStream destCdocOs = Files.newOutputStream(this.destCdocFile.toPath())) {

            Envelope.reEncrypt(
                inCdocIs,
                this.decryptionKeyMaterial,
                destCdocOs,
                this.reEncryptionKeyMaterial,
                destDir,
                this.services
            );
        } catch (Exception ex) {
            log.info("Exception, removing {}", destCdocFile);
            Files.deleteIfExists(destCdocFile.toPath());

            throw ex;
        }
    }

}
