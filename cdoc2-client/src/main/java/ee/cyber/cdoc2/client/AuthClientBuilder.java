package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;


/**
 * Builder for API client {@link Cdoc2AuthApiClient}.
 */
public class AuthClientBuilder extends ApiClientBuilder {

    /**
     * {@link Cdoc2AuthApiClient} builder
     *
     * @throws GeneralSecurityException when establishing TLS connection fails
     */
    public Cdoc2AuthApiClient build() throws GeneralSecurityException {
        ee.cyber.cdoc2.client.api.ApiClient apiClient = this.createApiClient();

        return new Cdoc2AuthApiClient(new ee.cyber.cdoc2.client.api.Cdoc2AuthApi(apiClient));
    }
}
