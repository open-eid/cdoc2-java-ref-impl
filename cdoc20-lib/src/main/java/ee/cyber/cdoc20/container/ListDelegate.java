package ee.cyber.cdoc20.container;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;

public class ListDelegate implements TarEntryProcessingDelegate {

    @Override
    public OP getType() {
        return OP.LIST;
    }

    @Nullable
    @Override
    public File onTarEntry(TarArchiveEntry tarEntry) throws IOException {
        return null;
    }

    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        // tar entry contents are not needed for list
    }

    @Override
    public boolean onEndOfTarEntry() throws IOException {
        return true;
    }

    @Nullable
    @Override
    public File getOutputDir() {
        return null;
    }

}
