package rsh.ott;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

import java.util.Properties;

record StartTls(Boolean enable){}
@Component
@Data
@ConfigurationProperties(prefix = "spring.mail.properties.mail.smtp")
class Smtp{String auth; StartTls startTls;}
@Component
@Data
@ConfigurationProperties(prefix = "spring.mail")
class Mail { String host; Integer port; String username; String password; }

@Configuration
public class OttMailConfiguration {

    @Autowired Mail mail;
    @Autowired Smtp smtp;

    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(mail.host);
        mailSender.setPort(mail.port);
        mailSender.setUsername(mail.username);
        mailSender.setPassword(mail.password);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.smtp.auth", smtp.auth);
        props.put("mail.smtp.starttls.enable", smtp.startTls.enable());

        return mailSender;
    }
}
