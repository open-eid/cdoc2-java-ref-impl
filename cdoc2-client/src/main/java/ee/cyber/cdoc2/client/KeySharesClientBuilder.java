package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;


/**
 * Builder for API client {@link Cdoc2KeySharesApiClient}.
 */
public class KeySharesClientBuilder extends ApiClientBuilder {

    /**
     * {@link Cdoc2KeySharesApiClient} builder
     */
    public Cdoc2KeySharesApiClient build() throws GeneralSecurityException {
        ee.cyber.cdoc2.client.api.ApiClient apiClient = this.createApiClient();

        return new Cdoc2KeySharesApiClient(new ee.cyber.cdoc2.client.api.Cdoc2KeySharesApi(apiClient));
    }

}
