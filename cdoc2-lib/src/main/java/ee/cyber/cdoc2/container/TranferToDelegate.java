package ee.cyber.cdoc2.container;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

/**
 * {@link TarEntryProcessingDelegate} that copies tar entries from tar input stream to tar output stream
 */
public class TranferToDelegate implements TarEntryProcessingDelegate {
    TarArchiveOutputStream tarArchiveOutputStream;

    /**if tar is in file system, then destPath */
    @Nullable Path destDir;

    public TranferToDelegate(TarArchiveOutputStream toTarOutputStream,
                             @Nullable Path destDir) {
        this.tarArchiveOutputStream = toTarOutputStream;
        this.destDir = destDir;
    }

    @Override
    public OP getType() {
        return OP.TRANSFER;
    }

    @Override
    @Nullable
    public File onTarEntry(TarArchiveEntry tarEntry) throws IOException {
        // Create tar entry in tarArchiveOutputStream
        tarArchiveOutputStream.putArchiveEntry(tarEntry);
        return null;
    }

    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        // write to output stream
        tarArchiveOutputStream.write(buf, off, len);
    }

    @Override
    public boolean onEndOfTarEntry() throws IOException {
        tarArchiveOutputStream.closeArchiveEntry();
        return true;
    }

    @Nullable
    @Override
    public File getOutputDir() {
        if (destDir != null) {
            return destDir.toFile();
        }
        return null;
    }
}
