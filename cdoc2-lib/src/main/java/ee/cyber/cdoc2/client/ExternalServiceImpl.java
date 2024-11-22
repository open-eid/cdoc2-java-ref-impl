package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;

import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;


/**
 * Implementation for common for servers client factory
 */
public class ExternalServiceImpl implements ExternalService {

    @Override
    public ExternalService initKeyCapsuleClientFactory(KeyCapsuleClientConfiguration config)
        throws GeneralSecurityException {
        return KeyCapsuleClientImpl.createFactory(config);
    }

    @Override
    public ExternalService initKeyShareClientFactory(KeySharesConfiguration config)
        throws GeneralSecurityException {
        return KeySharesClientHelper.createFactory(config);
    }

}
