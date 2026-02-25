package ee.cyber.cdoc2.client;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An {@link X509KeyManager} decorator that always returns a fixed alias, effectively
 * pinning the TLS handshake to a specific key/certificate entry in the keystore.
 * <p>
 * This is necessary when a PKCS11 token exposes multiple certificates and the JDK's
 * default {@code PKIX} KeyManagerFactory would otherwise select an alias arbitrarily.
 */
public record AliasForcingX509KeyManager(X509KeyManager delegate, String alias)
    implements X509KeyManager {

    private static final Logger log = LoggerFactory.getLogger(AliasForcingX509KeyManager.class);

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        for (String keyType : keyTypes) {
            String[] aliases = delegate.getClientAliases(keyType, issuers);
            if (aliases != null) {
                for (String candidate : aliases) {
                    X509Certificate[] chain = delegate.getCertificateChain(candidate);
                    if (chain != null && chain.length > 0) {
                        // The JSSE wraps the aliases with <unique-id>.<builder-index>.<real-alias>
                        if (candidate.endsWith(alias)) {
                            log.debug("Selected internal alias '{}' for requested alias '{}'", candidate, alias);
                            return candidate;
                        }
                    }
                }
            }
        }
        // fallback
        return delegate.chooseClientAlias(keyTypes, issuers, socket);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return delegate.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String keyAlias) {
        return delegate.getCertificateChain(keyAlias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return delegate.getClientAliases(keyType, issuers);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return delegate.getServerAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String keyAlias) {
        return delegate.getPrivateKey(keyAlias);
    }
}
