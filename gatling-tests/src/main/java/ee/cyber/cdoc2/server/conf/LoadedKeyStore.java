package ee.cyber.cdoc2.server.conf;

import java.io.File;
import java.security.PublicKey;

/**
 * Holds a key store that has been verified and loaded from a file
 */
public record LoadedKeyStore(
    PublicKey publicKey,
    File file,
    String keyStoreType, // pkcs12
    String password
) {
}
