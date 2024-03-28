package ee.cyber.cdoc2.container;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Validator for allowed file names in Tar archives
 */
public final class FileNameValidator {

    private static final Pattern WIN_RESERVED_NAMES = Pattern.compile(
        "^(CON|PRN|AUX|NUL|(COM|LPT)[1-9])$",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern WIN_RESERVED_SYMBOLS = Pattern.compile("[<>:\"/\\\\|?*]");

    private static final Pattern MASQUERADING_CHARACTERS = Pattern.compile("\u202E");

    private FileNameValidator() {
        // utility class
    }

    /**
     * Validates the filename for use in Tar file entries
     *
     * @param baseName the basename (filename without directory path)
     * @return the provided filename
     * @throws InvalidPathException if the filename is not valid
     */
    public static String validate(String baseName) {
        if (baseName == null || baseName.isEmpty()) {
            throw new InvalidPathException(baseName, "Filename cannot be empty.");
        }

        String errorMessage = null;

        if (baseName.endsWith(" ") || baseName.endsWith(".")) {
            errorMessage = "Filename cannot end with a space or period.";
        } else if (baseName.startsWith(" ")) {
            errorMessage = "Filename cannot start with a space.";
        } else if (baseName.startsWith("-")) {
            errorMessage = "Filename cannot start with a hyphen.";
        } else if (WIN_RESERVED_SYMBOLS.matcher(baseName).find()) {
            errorMessage = "Filename cannot contain reserved symbols.";
        } else if (WIN_RESERVED_NAMES.matcher(baseName).find()) {
            errorMessage = "Filename cannot be a reserved name.";
        } else if (MASQUERADING_CHARACTERS.matcher(baseName).find()) {
            errorMessage = "Filename cannot contain masquerading characters.";
        }


            // check for control characters
        for (char c: baseName.toCharArray()) {
            if (Character.getType(c) == Character.CONTROL) {
                errorMessage = "Filename cannot contain control symbols.";
                break;
            }
        }

        if (errorMessage != null) {
            throw new InvalidPathException(baseName, errorMessage);
        }
        return baseName;
    }

    /**
     * Validates there are no file duplicates in container before saving them into Tar archive
     *
     * @param files the list of files
     * @throws IllegalArgumentException if there are files duplicates
     */
    public static void ensureNoFileDuplicates(Iterable<File> files) {
        List<String> baseNameList = new LinkedList<>();
        files.forEach(f -> baseNameList.add(validate(f.getName())));
        List<String> distinctList = baseNameList.stream().distinct().toList();
        if (baseNameList.size() != distinctList.size()) {
            List<String> duplicates = baseNameList.stream()
                .filter(str -> Collections.frequency(baseNameList, str) > 1)
                .toList();

            List<File> duplicateFiles = new LinkedList<>();
            files.forEach(f -> {
                if (duplicates.contains(f.getName())) {
                    duplicateFiles.add(f);
                }
            });

            throw new IllegalArgumentException(
                "Files with same basename not supported: " + duplicateFiles
            );
        }
    }

}
