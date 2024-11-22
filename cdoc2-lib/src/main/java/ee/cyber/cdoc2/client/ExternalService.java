package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;

import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;


/**
 * Common factory for servers clients {@link KeyCapsuleClientFactory} and {@link KeyShareClientFactory}
 */
public interface ExternalService {

    default ExternalService initKeyCapsuleClientFactory(KeyCapsuleClientConfiguration config)
        throws GeneralSecurityException {
        return null;
    }

    default ExternalService initKeyShareClientFactory(KeySharesConfiguration config)
        throws GeneralSecurityException {
        return null;
    }

}
