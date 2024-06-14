package ee.cyber.cdoc2.converter.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

public class AutoRemovableDir implements AutoCloseable {

    Path pathToRemove;
    public AutoRemovableDir(Path pathToRemove) {
        this.pathToRemove = pathToRemove;
    }

    @Override
    public void close() throws IOException {
        if (pathToRemove.toFile().isDirectory()) {
            purgeDirectory(pathToRemove.toFile());
        }
        Files.delete(pathToRemove);
    }

    private static void purgeDirectory(File dir) {
        Objects.nonNull(dir);
        for (File file: dir.listFiles()) {
            if (file.isDirectory())
                purgeDirectory(file);
            file.delete();
        }
    }
}
