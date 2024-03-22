package ee.cyber.cdoc20.container;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.utils.InputStreamStatistics;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;

/**
 * Delegate to react on tar input processing events. Allows to perform different operation on tarEntry
 * depending on processing wanted. Currently, known outputs can be
 * * Extract - extract files from tar input stream to destination directory
 * * Transfer - copy tar entries from input tar stream to output tar stream. Useful for re-encryption.
 * * List - list tar entries found from tar input stream
 * @see {@link TarDeflate#processTarEntry(TarEntryProcessingDelegate, TarArchiveEntry,
 * TarArchiveInputStream, InputStreamStatistics)}
 */
public interface TarEntryProcessingDelegate {

    /**
     * Operation for process
     */
    enum OP {
        /** Extract files to dir*/
        EXTRACT,
        /** No extraction, return list of files in archive*/
        LIST,
        /** Transfer (copy) files to other tar for re-encryption*/
        TRANSFER
    }

    OP getType();

    /**
     * Called when TarArchiveEntry has been found from underlying tar input stream
     * @param tarEntry Tar Archive entry
     * @throws IOException if an I/O error occurs
     * @return File created or null if no file where created
     */
    @Nullable
    File onTarEntry(TarArchiveEntry tarEntry) throws IOException;

    /**
     * Write TarArchiveEntry contents
     * @param buf the buffer containing the data to be written
     * @param off the start offset in the buffer
     * @param len the number of bytes to write
     * @throws IOException if an I/O error occurs
     */
    void write(byte[] buf, int off, int len) throws IOException;

    /**

     * @return if tarEntry was processed (true) or ignored (false)
     * @throws IOException if an I/O error occurs
     */
    boolean onEndOfTarEntry() throws IOException;

    /**
     * Get directory where output is written. May be null
     * (for example for list or when output is not on filesystem)
     */
    @Nullable File getOutputDir();

}
