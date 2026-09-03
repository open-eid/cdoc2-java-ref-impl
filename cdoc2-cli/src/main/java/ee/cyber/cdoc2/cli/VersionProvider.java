package ee.cyber.cdoc2.cli;

import picocli.CommandLine.IVersionProvider;

import java.io.IOException;
import java.io.InputStream;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

public class VersionProvider implements IVersionProvider {

    private static final String UNKNOWN_VERSION = "unknown";

    @Override
    public String[] getVersion() throws IOException {
        Attributes attributes = readManifestAttributes();

        return new String[] {
            "cdoc2-cli version: " + attributes.getValue("Implementation-Version"),
            "cdoc2-lib version: " + attributes.getValue("Cdoc2-Lib-Version")
        };
    }

    private Attributes readManifestAttributes() throws IOException {
        Attributes attributes = new Attributes();
        attributes.putValue("Implementation-Version", UNKNOWN_VERSION);
        attributes.putValue("Cdoc2-Lib-Version", UNKNOWN_VERSION);

        try (InputStream in = getClass().getResourceAsStream("/META-INF/MANIFEST.MF")) {
            if (in != null) {
                Attributes manifestAttributes = new Manifest(in).getMainAttributes();
                for (Object key : manifestAttributes.keySet()) {
                    attributes.putValue(key.toString(), manifestAttributes.getValue(key.toString()));
                }
            }
        }

        return attributes;
    }
}
