package rsh.conf;

import com.webauthn4j.WebAuthnManager;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import rsh.api.TestEnvRestController;
import rsh.ott.OttMail;
import rsh.user.UserRepository;

import java.io.IOException;

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
                        .requestMatchers("/h2-console/**").permitAll()
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
                .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
                .exceptionHandling(ex -> {
                    // Added this, because I often forget the csrf fields using jte
                  ex.accessDeniedHandler(new AccessDeniedHandler() {
                      @Override
                      public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                          System.err.println(accessDeniedException);
                          new AccessDeniedHandlerImpl().handle(request,response,accessDeniedException);
                      }
                  });
                })
                .build();
    }
}
