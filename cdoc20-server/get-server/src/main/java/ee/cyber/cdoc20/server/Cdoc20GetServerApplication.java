package ee.cyber.cdoc20.server;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.Ssl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;


@SpringBootApplication
@Configuration
@EnableWebSecurity
@EnableJpaAuditing
@Slf4j
public class Cdoc20GetServerApplication extends WebSecurityConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(Cdoc20GetServerApplication.class, args);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //https://github.com/eugenp/tutorials/tree/master/spring-security-modules/spring-security-web-x509
        //everything else not ignored from WebSecurity will need client certificate
        http.authorizeRequests().anyRequest().authenticated()
            .and()
                .x509()
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService())
            .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
            .and()
                .csrf()
                .disable();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // UserDetailsService required by TomCat or it will fail on runtime
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String cn) throws UsernameNotFoundException {
                // Real authentication is done by service
                // required to force Spring to ask user certificate
                // see EccDetailsApiDelegateImpl
                log.debug("CN={}", cn);
                return new User(cn, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
            }
        };
    }

    /**
     * Checks that the application is configured with mutual TLS.
     * @param event the context
     * @throws IllegalStateException when mutual TLS is not configured
     */
    @EventListener
    public static void checkMutualTlsConfigured(ContextRefreshedEvent event) {
        var env = event.getApplicationContext().getEnvironment();
        var clientAuth = env.getRequiredProperty("server.ssl.client-auth");

        if (Ssl.ClientAuth.NEED != Ssl.ClientAuth.valueOf(clientAuth.toUpperCase())) {
            throw new IllegalStateException("TLS client authentication not enabled");
        }
    }
}
