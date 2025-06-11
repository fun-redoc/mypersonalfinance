package rsh.ott;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class OttMail {
    @Autowired
    EmailService emailService;

        private final JavaMailSenderImpl mailSender;

        private final HttpServletRequest currentRequest;

        public OttMail(JavaMailSenderImpl mailSender, HttpServletRequest httpServletRequest) {
            this.mailSender = mailSender;
            this.currentRequest = httpServletRequest;
        }

        public void notify(String email, String user, String title, String token) {
            var builder =
                    UriComponentsBuilder
                            .fromUriString(UrlUtils.buildFullRequestUrl(currentRequest))
                            .replacePath("/login/ott");
            String bareUrl = builder.toUriString();

            builder.replaceQuery(null)
                    .fragment(null)
                    //.path("/login/ott")
                    .queryParam("token", token);

            String link = builder.toUriString();

            emailService.sendEmail(email, bareUrl, user, token,  link);
        }

    }
