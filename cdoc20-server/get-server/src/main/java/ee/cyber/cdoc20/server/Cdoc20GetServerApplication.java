package ee.cyber.cdoc20.server;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
}
