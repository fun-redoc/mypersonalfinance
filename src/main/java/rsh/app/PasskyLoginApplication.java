package rsh.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import com.fasterxml.jackson.databind.ObjectMapper;
import rsh.api.TestEnvRestController;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.io.InputStream;

@SpringBootApplication
//@ComponentScan(basePackages = {"rsh.conf", "rsh.user", "rsh.ott", "rsh.web"})
@ComponentScan(basePackages = {"rsh.**"})
@EnableJpaRepositories(basePackages = {"rsh.user","rsh.domain.**"})
@EntityScan(basePackages = {"rsh.user", "rsh.domain.**"})
public class PasskyLoginApplication {

	@Autowired
	UserRepository userRepository;


	public static void main(String[] args) {
		SpringApplication.run(PasskyLoginApplication.class, args);
	}

	@Bean
	@Profile("devel")
	CommandLineRunner runner() {
		// preloads a user for testesing.
		// you can create the user using the registration procedure first
		// and saving the resunt of the api call to /api/self/details
		// to /src/resources/data/details.json
		return args -> {

			try {
				var mapper = new ObjectMapper();
				var inputStream = new ClassPathResource("data/details.json");
				var userEntity = mapper.readValue(inputStream.getInputStream(), UserEntity.class);
				userRepository.save(userEntity);
			} catch (Exception e) {
				System.err.println("could not create testdata and testuser.");
				System.err.println(e);
			}
		};
	}
}
