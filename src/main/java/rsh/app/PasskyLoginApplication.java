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
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import rsh.api.TestEnvRestController;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.AccountsBaseData;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.io.InputStream;
import java.util.*;

@SpringBootApplication
//@ComponentScan(basePackages = {"rsh.conf", "rsh.user", "rsh.ott", "rsh.web"})
@ComponentScan(basePackages = {"rsh.**"})
@EnableJpaRepositories(basePackages = {"rsh.user","rsh.domain.**"})
@EntityScan(basePackages = {"rsh.user", "rsh.domain.**"})
public class PasskyLoginApplication {

	//@Autowired
	//UserRepository userRepository;
	//@Autowired
	//OwnerEntity ownerEntity;


	public static void main(String[] args) {
		SpringApplication.run(PasskyLoginApplication.class, args);
	}

	@Bean
	@Profile("devel")
	CommandLineRunner runner(TransactionTemplate transactionTemplate,
							 UserRepository userRepository,
							 OwnerRepository ownerRepository,
							 AccountRepository accountRepository) {
		// preloads a user and other data for testesing.
		// you can create a user using the registration procedure first
		// and saving the resunt of the api call to /api/self/details
		// to /src/resources/data/details.json
		return args -> {
			var u1 = transactionTemplate.execute(status -> {
						// UserEntity
						try {
							var mapper = new ObjectMapper();
							var inputStream = new ClassPathResource("data/details.json");
							var userEntity = mapper.readValue(inputStream.getInputStream(), UserEntity.class);
							userRepository.save(userEntity);
							return userEntity;
						} catch (Exception e) {
							System.err.println("could not create testdata and testuser.");
							System.err.println(e);
							return null;
						}
					});

			transactionTemplate.execute(status -> {
						// Owners
						var group1 = ownerRepository.save(OwnerEntity.builder().admin(u1).name("group1").users(new HashSet<>()).build().addUser(u1));
						var group2 = ownerRepository.save(OwnerEntity.builder().admin(u1).name("group2").users(new HashSet<>()).build().addUser(u1));
						var group3 = ownerRepository.save(OwnerEntity.builder().admin(u1).name("group3").users(new HashSet<>()).build());
						return null;
					});

			// Accounts
				try {
					var mapper = new ObjectMapper();
					var inputStream = new ClassPathResource("data/accounts.json");
					AccountsBaseData[] accounts = mapper.readValue(inputStream.getInputStream(), AccountsBaseData[].class);
					Arrays.stream(accounts)
						.map(accountBase ->
								AccountEntity.builder()
									//.id(accountBase.getId())
									.iban(accountBase.getIban())
									.bank((accountBase.getBank()))
									.belongsTo(OwnerEntity.builder().id(accountBase.getOwnerId()).build())
									.dateCreated(Calendar.getInstance().getTime())
									.accountType(accountBase.getAccountType())
									.dateClosed(null)
									.name(accountBase.getName())
								.build())
							.forEach(accountEntity -> {
								transactionTemplate.execute(status -> {
									accountRepository.save(accountEntity);
									return null;
								});
							});
				} catch (Exception e) {
					System.err.println("could not create testdata for accounts.");
					System.err.println(e);
				}

		};
	}
}
