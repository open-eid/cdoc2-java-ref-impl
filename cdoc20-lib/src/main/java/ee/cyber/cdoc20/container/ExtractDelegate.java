package ee.cyber.cdoc20.container;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class ExtractDelegate implements TarEntryProcessingDelegate {

    private Path destDir;

    @Nullable
    private List<String> filesToExtract; // null means all files

    private FileOutputStream fileOutputStream;

    public ExtractDelegate(
        Path destDir,
        @Nullable List<String> filesToExtract
    ) {

        if (!isDirectoryWritable(destDir)) {
            throw new IllegalArgumentException("Not a directory or not writeable " + destDir);
        }

        this.destDir = destDir;
        this.filesToExtract = filesToExtract;
    }

    @Override
    public OP getType() {
        return OP.EXTRACT;
    }

    @Override
    public File onTarEntry(TarArchiveEntry tarEntry) throws IOException {
        if ((filesToExtract == null) || filesToExtract.contains(tarEntry.getName())) {
            File outFile = TarDeflate.pathFromTarEntry(destDir, tarEntry, true).toFile();
            fileOutputStream = new FileOutputStream(outFile);
            return outFile;
        }
        return null;
    }

    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        if (fileOutputStream != null) { // file was created and needs extracting
            fileOutputStream.write(buf, off, len);
        }
    }

    @Override
    public boolean onEndOfTarEntry() throws IOException {
        if (fileOutputStream != null) { // file was created and needs to be closed
            fileOutputStream.close();
            return true;
        }
        return false;
    }

    @Override
    public File getOutputDir() {
        if (destDir != null) {
            return destDir.toFile();
        }
        return null;
    }

    private boolean isDirectoryWritable(Path outputDir) {
        return (outputDir != null) && Files.isDirectory(outputDir) && Files.isWritable(outputDir);
    }

}
