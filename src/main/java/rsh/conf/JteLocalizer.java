package rsh.conf;

import gg.jte.Content;
import gg.jte.TemplateOutput;
import gg.jte.support.LocalizationSupport;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.Locale;

@Configuration
public class JteLocalizer implements gg.jte.support.LocalizationSupport {

    ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();

    @Bean
    JteLocalizer getBean() {
        return this;
    }

    public JteLocalizer() {
        messageSource.setBasename("Messages");
        //this.frameworkLocalizer = frameworkLocalizer;
    }

    @Override
    public String lookup(String key) {
        // However this works in your localization framework
        //return frameworkLocalizer.get(locale, key);
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
        //return LocalizationSupport.super.localize(key, params, locale);
    }
}
