package rsh.app;
import org.junit.Before;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.*;
import org.openqa.selenium.By;

import org.junit.After;
import org.junit.Test;

// given up, didn'tt manage to install browser drivers properly, nither gecko nor chrome worked for me.
public class SeleniumTests {
    private WebDriver webDriver;

    @Before
    public void setup() {
        FirefoxOptions firefoxOptions = new FirefoxOptions();
        firefoxOptions.addArguments("--remote-allow-origins=*");
        firefoxOptions.setAcceptInsecureCerts(true);
        firefoxOptions.setBinary("/home/rsh/Software/geckodriver");
        webDriver = new FirefoxDriver(firefoxOptions);
    }
    @Test
    public void test() {
        webDriver.get("https://localhost:8443/settings");
    }

    @After
    public void tearDown() {
        webDriver.quit();
    }
}
