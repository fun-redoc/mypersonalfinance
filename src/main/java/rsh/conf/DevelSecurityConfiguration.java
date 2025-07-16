package rsh.conf;

import com.webauthn4j.WebAuthnManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import rsh.api.TestEnvRestController;
import rsh.ott.OttMail;
import rsh.user.UserRepository;

@Profile("devel")
@Configuration
@EnableWebSecurity
public class DevelSecurityConfiguration {
    @Autowired
    UserRepository userRepository;

    @Profile("devel")
    @Bean
    SecurityFilterChain develSecurityFilterChainMy(HttpSecurity httpSecurity) throws Exception {
    //SecurityFilterChain develSecurityFilterChainMy(HttpSecurity httpSecurity, OttMail ottMail) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(auth-> auth
                        .anyRequest().permitAll()
                )
                .addFilterAfter(new DevelLogonSecurityFilter(userRepository),
                        FilterSecurityInterceptor.class)
                .logout(logout -> logout
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/logon?logout")
                        .permitAll()
                )
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                )
                .csrf(Customizer.withDefaults())
                .build();
    }
}
