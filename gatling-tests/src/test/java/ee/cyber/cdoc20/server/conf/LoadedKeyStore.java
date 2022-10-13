package ee.cyber.cdoc20.server.conf;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.io.File;
import java.security.interfaces.ECPublicKey;

/**
 * Holds a key store that has been verified and loaded from a file
 */
@Getter
@RequiredArgsConstructor
public class LoadedKeyStore {
    private final ECPublicKey publicKey;
    private final File file;
    private final String type;
    private final String password;
}
