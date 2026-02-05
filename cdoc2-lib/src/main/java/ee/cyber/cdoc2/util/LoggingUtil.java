package ee.cyber.cdoc2.util;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;


/**
 * Utility class containing methods used for logging
 */
public final class LoggingUtil {
    private LoggingUtil() {
        // utility class
    }

    /**
     * Censors the file name for logs. E.g. "hello.txt" would be "xxxxx.txt".
     *
     * @param fileName filename
     * @return The censored filename
     */
    public static String censorFileName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return fileName;
        }

        int lastDotIndex = fileName.lastIndexOf('.');

        // No extension or dot is the first character (e.g. ".gitignore")
        if (lastDotIndex <= 0) {
            return "X".repeat(fileName.length());
        }

        String namePart = fileName.substring(0, lastDotIndex);
        String extensionPart = fileName.substring(lastDotIndex);

        return "X".repeat(namePart.length()) + extensionPart;
    }

    /**
     * Censors the file path for logs. E.g. "abc/aaa/hello.txt" would be "abc/aaa/xxxxx.txt".
     *
     * @param path file path
     * @return censored file path as string
     */
    public static String censorPathFileName(Path path) {
        if (path == null) {
            return null;
        }

        Path fileName = path.getFileName();
        if (fileName == null) {
            return path.toString();
        }

        String censoredFileName = censorFileName(fileName.toString());

        Path parent = path.getParent();
        if (parent == null) {
            return censoredFileName;
        }

        return parent.resolve(censoredFileName).toString();
    }

    public static List<String> censorFileNames(File[] files) {
        if (files == null) {
            return null;
        }

        List<String> result = new ArrayList<>(files.length);

        for (File file : files) {
            if (file == null) {
                result.add(null);
                continue;
            }

            String censoredName = censorFileName(file.getName());
            result.add(censoredName);
        }

        return result;
    }
}
