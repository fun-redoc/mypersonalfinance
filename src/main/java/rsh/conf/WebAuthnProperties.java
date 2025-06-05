package rsh.conf;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "authn")
public class WebAuthnProperties {
    private String hostname;
    private String display;
    private String origin;

    public WebAuthnProperties() {
    }

    public WebAuthnProperties(String hostname, String display, String origin) {
        this.hostname = hostname;
        this.display = display;
        this.origin = origin;
    }

    public void setFrom(WebAuthnProperties other) {
        this.hostname = other.hostname;
        this.display = other.display;
        this.origin = other.origin;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getDisplay() {
        return display;
    }

    public void setDisplay(String display) {
        this.display = display;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }
}
