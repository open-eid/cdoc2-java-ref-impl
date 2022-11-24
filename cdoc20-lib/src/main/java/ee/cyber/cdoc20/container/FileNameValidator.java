package ee.cyber.cdoc20.container;

import java.nio.file.InvalidPathException;
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
}
