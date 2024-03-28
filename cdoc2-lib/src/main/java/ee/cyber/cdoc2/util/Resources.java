package ee.cyber.cdoc2.util;

import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Utility class for loading resources (ex. properties files) from classpath
 */
public final class Resources {

    private Resources() { }
    /**
     * Load resource from classpath or file as InputStream.
     * @param name starts with classpath: then loads resource from classpath otherwise reads from file
     * @return a new input stream created from name
     * @throws IOException if an I/O error occurs
     * @throws NullPointerException if name is null
     */
    public static InputStream getResourceAsStream(String name) throws IOException {
        return getResourceAsStream(name, null);
    }

    /**
     * Load resource from classpath or file as InputStream.
     * @param name starts with classpath: then loads resource from classpath otherwise reads from file
     * @param cl optional ClassLoader to load the resource
     * @return a new input stream created from name
     * @throws IOException if an I/O error occurs
     * @throws NullPointerException if name is null
     */
    public static InputStream getResourceAsStream(String name, @Nullable ClassLoader cl) throws IOException {
        final String classpath = "classpath:";
        Objects.requireNonNull(name);

        ClassLoader classLoader = (cl != null) ? cl : KeyCapsuleClientImpl.class.getClassLoader();

        if (name.startsWith(classpath) && (name.length() > classpath.length())) {
            return classLoader.getResourceAsStream(name.substring(classpath.length()));
        } else {
            return Files.newInputStream(Path.of(name));
        }
    }
}
