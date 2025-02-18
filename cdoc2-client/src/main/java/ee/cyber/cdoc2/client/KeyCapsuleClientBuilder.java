package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;


/**
 * Builder for API client {@link Cdoc2KeyCapsuleApiClient}.
 */
public class KeyCapsuleClientBuilder extends ApiClientBuilder {

    /**
     * {@link Cdoc2KeyCapsuleApiClient} builder
     */
    public Cdoc2KeyCapsuleApiClient build() throws GeneralSecurityException {
        ee.cyber.cdoc2.client.api.ApiClient apiClient = this.createApiClient();

        return new Cdoc2KeyCapsuleApiClient(new ee.cyber.cdoc2.client.api.Cdoc2KeyCapsulesApi(apiClient));
    }

}
