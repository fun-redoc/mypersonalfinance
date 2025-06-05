package rsh.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
//@ComponentScan(basePackages = {"rsh.conf", "rsh.user", "rsh.ott", "rsh.web"})
@ComponentScan(basePackages = {"rsh.**"})
@EnableJpaRepositories(basePackages = {"rsh.user"})
@EntityScan(basePackages = {"rsh.user"})
public class PasskyLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(PasskyLoginApplication.class, args);
	}

}
