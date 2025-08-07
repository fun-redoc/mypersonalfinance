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
import rsh.domain.account.deposit.DepositEntity;
import rsh.domain.account.deposit.DepositRepository;
import rsh.domain.account.deposit.TagEntity;
import rsh.domain.account.deposit.TagRepository;
import rsh.domain.account.deposit.interest.FlatInterestEntity;
import rsh.domain.account.deposit.interest.InterestRepository;
import rsh.domain.account.post.PostEntity;
import rsh.domain.account.post.PostRepository;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.io.InputStream;
import java.math.BigDecimal;
import java.time.temporal.ChronoUnit;
import java.time.temporal.IsoFields;
import java.time.temporal.TemporalUnit;
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
							 AccountRepository accountRepository,
							 TagRepository tagRepository,
							 InterestRepository interestRepository,
							 PostRepository postRepository,
							 DepositRepository depositRepository
	) {
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
		transactionTemplate.execute(status -> {
			// posts
			var accounts = accountRepository.findByUser(u1);
			assert accounts.size() >= 2;
			var account0 = accounts.get(0);
			var account1 = accounts.get(1);
			var post1 = postRepository.save(
					PostEntity.builder()
							.date(Calendar.getInstance().getTime())
							.name(String.format("Post from %s to %s", account0.getName(), account1.getName()))
							.fromAccount(account0)
							.toAccount(account1)
							.amount(BigDecimal.ONE)
							.build());
			//assertThat(post1).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");
			var post2 = postRepository.save(
					PostEntity.builder()
							.date(Calendar.getInstance().getTime())
							.name(String.format("Post from %s to %s", account0.getName(), account1.getName()))
							.fromAccount(account0)
							.toAccount(account1)
							.amount(BigDecimal.ONE)
							.build());
			//assertThat(post2).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");
			var post3 = postRepository.save(
					PostEntity.builder()
							.date(Calendar.getInstance().getTime())
							.name(String.format("Post from %s to %s", account0.getName(), account1.getName()))
							.fromAccount(account0)
							.toAccount(account1)
							.amount(BigDecimal.ONE)
							.build());
			//assertThat(post3).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");
			// a free post
			var post4 = postRepository.save(
					PostEntity.builder()
							.date(Calendar.getInstance().getTime())
							.name(String.format("Post from %s to %s", account0.getName(), account1.getName()))
							.fromAccount(account0)
							.toAccount(account1)
							.amount(BigDecimal.ONE)
							.build());
			//assertThat(post4).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");
			// a free post
			var post5 = postRepository.save(
					PostEntity.builder()
							.date(Calendar.getInstance().getTime())
							.name(String.format("Post from %s to %s", account0.getName(), account1.getName()))
							.fromAccount(account0)
							.toAccount(account1)
							.amount(BigDecimal.ONE)
							.build());
			//assertThat(post5).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");

			// deposit
			var startDate = Calendar.getInstance();
			var endDate = Calendar.getInstance();
			endDate.add(Calendar.YEAR,1);

			var startDate1 = Calendar.getInstance();
			var endDate1 = Calendar.getInstance();
			startDate1.add(Calendar.YEAR,-2);
			endDate1.add(Calendar.YEAR,-1);

			var tag1 = tagRepository.save(TagEntity.builder()
					.name("tag 1")
					.deposits(new HashSet<DepositEntity>())
					.build());
			//assertThat(tag1).isNotNull().hasFieldOrPropertyWithValue("id", 1L);
			var tag2 = tagRepository.save(TagEntity.builder()
					.name("tag 2")
					.deposits(new HashSet<DepositEntity>())
					.build());
			//assertThat(tag2).isNotNull().hasFieldOrPropertyWithValue("id", 2L);
			var tag3 = tagRepository.save(TagEntity.builder()
					.name("tag 3")
					.deposits(new HashSet<DepositEntity>())
					.build());
			//assertThat(tag3).isNotNull().hasFieldOrPropertyWithValue("id", 3L);
			var interest = interestRepository.save(
					FlatInterestEntity.builder()
							.begin(startDate.getTime())
							.annualRate(BigDecimal.valueOf(0.025))
							.finish(endDate.getTime()).build());
			//assertThat(interest).isNotNull().hasFieldOrPropertyWithValue("id", 1L);
			var deposit1 = depositRepository
					.save(
							DepositEntity.builder()
									.interest( interest )
									.begin(startDate1.getTime())
									.due(endDate1.getTime())
									.belongsTo(ownerRepository.findOwnerByName("group1").orElseThrow())
									.name("test deposit with flat interest of 2.5% over 2 years")
									.account(account1)
									.posts(new ArrayList<>())
									.tags(new HashSet<TagEntity>())
									.build().addTag(tag1).addTag(tag2).addPost(post1).addPost(post2));
			//assertThat(deposit1).isNotNull().hasFieldOrPropertyWithValue("id", 1L);
			var deposit2 = depositRepository
					.save(
							DepositEntity.builder()
									.interest( interest )
									.begin(startDate.getTime())
									.due(endDate.getTime())
									.belongsTo(ownerRepository.findOwnerByName("group1").orElseThrow())
									.name("test deposit2 with flat interest of 2.5% over 2 years")
									.account(account)
									.posts(new ArrayList<>())
									.tags(new HashSet<TagEntity>())
									.build().addTag(tag2).addTag(tag3).addPost(post3));
			//assertThat(deposit1).isNotNull().hasFieldOrPropertyWithValue("id", 1L);
			return null;
		});
		};
	}
}
