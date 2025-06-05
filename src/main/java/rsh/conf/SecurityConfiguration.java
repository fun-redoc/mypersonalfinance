package rsh.conf;

import com.webauthn4j.WebAuthnManager;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import rsh.ott.OttMail;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    OneTimeTokenGenerationSuccessHandler ottSuccessHandler =
            new RedirectOneTimeTokenGenerationSuccessHandler( "/ott/sent");

    @Bean static WebAuthnManager webAuthnManager() {
        return WebAuthnManager.createNonStrictWebAuthnManager();
    }

    @Bean
    SecurityFilterChain securityFilterChainMy(HttpSecurity httpSecurity, OttMail ottMail) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(auth-> auth
                        .requestMatchers(HttpMethod.GET,"/*.js").permitAll()
                        .requestMatchers(HttpMethod.GET,"/favicon.ico").permitAll()
                        .requestMatchers(HttpMethod.GET,"/").permitAll()
                        .requestMatchers("/sendEmail").permitAll()
                        .requestMatchers("/logon").permitAll()
                        //.requestMatchers("/registration").permitAll()
                        //.requestMatchers("/login").permitAll()
                        .requestMatchers("/login/ott").permitAll()
                        .requestMatchers("/ott/sent").permitAll()
                        .requestMatchers("/ott/fail").permitAll()
                        .requestMatchers("/login/passkey").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                )
                //.formLogin(Customizer.withDefaults())
                .oneTimeTokenLogin(ott -> { ott
                    .tokenGenerationSuccessHandler((request, response, authentication) -> {
                        var token = authentication.getTokenValue();
                        System.out.println("📩 Got token: " + token);
                        // remember username and email within the session
                        // registration will take over the entries
                        var n = request.getParameter("username");
                        var e = request.getParameter("email");
                        request.getSession().setAttribute("username", n);
                        request.getSession().setAttribute("email", e);
                        // TODO title etc. make configurable
                        try {
                            ottMail.notify(e,n, "Demo app log in",  token);
                            System.out.println("🍪 Token: " + token);
                            ottSuccessHandler.handle(request, response, authentication);
                        } catch (Exception ex) {
                            System.err.println(ex);
                            new RedirectOneTimeTokenGenerationSuccessHandler("/ott/fail").handle(request,response, null);
                        }
                    })
                        //.authenticationFailureHandler(new AuthenticationFailureHandler() {
                        //                                  @Override
                        //                                  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        //                                      System.err.println("ERROR login/ott");
                        //                                  }
                        //                              })
                    .authenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/registration"))
                    .showDefaultSubmitPage(false);
                })
                .addFilterBefore(new MySecurityFilter(), FilterSecurityInterceptor.class)
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
