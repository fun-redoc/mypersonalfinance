package rsh.ott;

import gg.jte.CodeResolver;
import gg.jte.ContentType;
import gg.jte.TemplateEngine;
import gg.jte.output.StringOutput;
import gg.jte.resolve.DirectoryCodeResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.Map;

@Service
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Autowired
    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
        // TODO use precompiling in production
        CodeResolver codeResolver = new DirectoryCodeResolver(Path.of("src/main/jte")); // This is the directory where your .jte files are located.
        this.templateEngine = TemplateEngine.create(codeResolver, ContentType.Html);
    }

    public void sendEmail(String to, String name, String link) {
        // Generate email content using JTE
        StringOutput output = new StringOutput();
        templateEngine.render("ottmail.jte", Map.of("target", link, "name", name),output);
        String emailContent = output.toString();

        // Send email
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Registration");
        message.setText(emailContent);
        mailSender.send(message);
    }
}

