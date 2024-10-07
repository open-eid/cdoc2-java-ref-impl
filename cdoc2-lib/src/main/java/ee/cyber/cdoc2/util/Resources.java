package ee.cyber.cdoc2.util;

import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;


/**
 * Utility class for loading resources (ex. properties files) from classpath
 */
public final class Resources {

    public static final String CLASSPATH = "classpath:";

    private Resources() { }
    /**
     * Load resource from classpath or file as InputStream.
     * @param name starts with classpath: then loads resource from classpath otherwise reads from file
     * @return a new input stream created from name
     * @throws ConfigurationLoadingException if failed to read properties from filesystem
     * or file path is missing
     */
    public static InputStream getResourceAsStream(String name) throws ConfigurationLoadingException {
        return getResourceAsStream(name, null);
    }

    /**
     * Load resource from classpath or file as InputStream.
     * @param filePath starts with classpath: then loads resource from classpath otherwise reads from file
     * @param cl optional ClassLoader to load the resource
     * @return a new input stream created from filePath
     * @throws ConfigurationLoadingException if failed to read properties from filesystem
     * or file path is missing
     */
    public static InputStream getResourceAsStream(String filePath, @Nullable ClassLoader cl)
        throws ConfigurationLoadingException {

        validateFilePath(filePath);

        ClassLoader classLoader = (cl != null) ? cl : KeyCapsuleClientImpl.class.getClassLoader();

        if (filePath.startsWith(CLASSPATH) && (filePath.length() > CLASSPATH.length())) {
            return classLoader.getResourceAsStream(filePath.substring(CLASSPATH.length()));
        } else {
            return readFromFilesystem(filePath);
        }
    }

    private static void validateFilePath(String filePath) {
        if (null == filePath) {
            throw new ConfigurationLoadingException("Property file path is missing");
        }
    }

    private static InputStream readFromFilesystem(String name) throws ConfigurationLoadingException {
        try {
            Path fileAbsolutePath = Path.of(new File(name).getAbsolutePath());
            return Files.newInputStream(fileAbsolutePath);
        } catch (IOException e) {
            throw new ConfigurationLoadingException(
                "Failed to read properties from file \"" + name + "\"", e
            );
        }
    }

}
