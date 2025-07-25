package rsh.conf;

import gg.jte.Content;
import gg.jte.TemplateOutput;
import gg.jte.support.LocalizationSupport;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.Locale;
import java.util.Optional;

@Configuration
public class JteLocalizer implements gg.jte.support.LocalizationSupport {

    ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();

    //@Bean
    //JteLocalizer getBean() {
    //    return this;
    //}

    public JteLocalizer() {
        messageSource.setBasename("Messages");
    }

    @Override
    public String lookup(String key) {
        var locale = LocaleContextHolder.getLocale();
        return messageSource.getMessage(key, null, locale);
    }


    @Override
    public Content localize(String key, Object... params) {
        var locale = LocaleContextHolder.getLocale();
        return  new Content() {
            @Override
            public void writeTo(TemplateOutput templateOutput) {
                templateOutput.writeContent(messageSource.getMessage(key, params, locale));
            }
        };
    }

    public boolean containsKey(String key) {
        var locale = LocaleContextHolder.getLocale();
        try { // this is so ugly
            messageSource.getMessage(key, null, locale);
            return true;
        } catch (NoSuchMessageException e) {
            return false;
        }
    }
    public Optional<Content> get(String key, Object... params) {
        var locale = LocaleContextHolder.getLocale();
        try{
            var message = messageSource.getMessage(key, params, locale);
            return Optional.of(  new Content() {
                @Override
                public void writeTo(TemplateOutput templateOutput) {
                    templateOutput.writeContent(message);
                }
            });
        } catch (NoSuchMessageException _) {
           return Optional.empty();
        }
    }
}
