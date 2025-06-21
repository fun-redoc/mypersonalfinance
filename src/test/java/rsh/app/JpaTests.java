package rsh.app;

import jakarta.transaction.Transactional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.deposit.DepositEntity;
import rsh.domain.account.deposit.DepositRepository;
import rsh.domain.account.deposit.TagEntity;
import rsh.domain.account.deposit.TagRepository;
import rsh.domain.account.deposit.interest.FlatInterestEntity;
import rsh.domain.account.deposit.interest.InterestRepository;
import rsh.domain.aggregates.Balance;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.domain.account.post.PostEntity;
import rsh.domain.account.post.PostRepository;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.math.BigDecimal;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;

//@SpringBootTest
@ActiveProfiles("test")
@DataJpaTest
//@ComponentScan(basePackages = {"rsh.account"},
//		       excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = {PasskyLoginApplication.class, OttMail.class}))
//@EnableJpaRepositories(basePackages = {"rsh.account"})
//@EntityScan(basePackages = {"rsh.account", "rsh.user"})
@MockBean(jakarta.servlet.http.HttpServletRequest.class)
@MockBean(org.springframework.security.web.SecurityFilterChain.class)
@MockBean(rsh.domain.account.AccountService.class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE) // Optional: Use real DB
class JpaTests {
	private static final Logger logger = LoggerFactory.getLogger(JpaTests.class);
	private static List<String> ibans = List.of(
			"DE02120300000000202051",
			"DE02500105170137075030",
			"DE02100500000054540402",
			"DE02300209000106531065",
			"DE02200505501015871393",
			"DE02100100100006820101",
			"DE02300606010002474689",
			"DE02600501010002034304",
			"DE02700202700010108669",
			"DE02700100800030876808",
			"DE02370502990000684712",
			"DE88100900001234567892",
			"DE02701500000000594937"
	);
	private static final int NUM_ACCOUNTS = 10;
	@Autowired
	AccountRepository accountRepository;
	@Autowired
	OwnerRepository ownerRepository;
	@Autowired
	UserRepository userRepository;
	@Autowired
	PostRepository postRepository;
	@Autowired
	TagRepository tagRepository;
	@Autowired
	DepositRepository depositRepository;
	@Autowired
	InterestRepository interestRepository;

	@Autowired
	Balance balance;

	@AfterEach
	public void cleanup() {

	}

	@BeforeEach
	@Transactional
	public  void startup(@Autowired UserRepository userRepository,
							   @Autowired OwnerRepository ownerRepository,
							   @Autowired AccountRepository accountRepository) {
		logger.info("<<<<< startup ");
		var u1 = userRepository.save(UserEntity.builder().id("t1").username("testuser1").email("testuser1@example.com").owners(new HashSet<>()).build());
		var u2 = userRepository.save(UserEntity.builder().id("t2").username("testuser2").email("testuser2@example.com").owners(new HashSet<>()).build());
		var u3 = userRepository.save(UserEntity.builder().id("t3").username("testuser3").email("testuser3@example.com").owners(new HashSet<>()).build());
		var u4 = userRepository.save(UserEntity.builder().id("t4").username("testuser4").email("testuser4@example.com").owners(new HashSet<>()).build());
		var group1 = ownerRepository.save(OwnerEntity.builder().name("group1").users(new HashSet<>()).build().addUser(u1).addUser(u2));
		var group2 = ownerRepository.save(OwnerEntity.builder().name("group2").users(new HashSet<>()).build().addUser(u3).addUser(u4));
		var group3 = ownerRepository.save(OwnerEntity.builder().name("group3").users(new HashSet<>()).build().addUser(u2).addUser(u3));
		var groups = List.of(group1, group2, group3);
		for(int i=0; i < ibans.size(); i++) {
			var a = AccountEntity.builder()
					.bank("bank")
					.iban(ibans.get(i))
					.accountType(AccountEntity.AccountType.BANK)
					.belongsTo(groups.get(i%(groups.size())))
					.dateCreated(Calendar.getInstance().getTime())
					.name(String.format("testaccount %d", i+1))
					.build();
			var a1 = accountRepository.save(a);
		}
		logger.info("startup >>>>>");
	}

	@Test
	@Transactional
	public void allAccounts() {
		logger.info("<<<<< allAccounts ");
		//List<AccountEntity> accountEntities = accountRepository.allAccounts(); // <-- 7 statements
		List<AccountEntity> accountEntities = accountRepository.findWithOwnerWithUserBy(); // 1 statement with JOIN FETCH Query
		assertThat(accountEntities).size().isEqualTo(ibans.size());
		for(var account:accountEntities) {
			//logger.info(account.toString());
			var names = account.getBelongsTo().getUsers().stream().map(UserEntity::getUsername).collect(Collectors.joining(", "));
			logger.info(String.format("iban %s, group: %s, users [%s]", account.getIban(),
					account.getBelongsTo().getName(),
					names
			));
			assertThat(names).isNotEmpty().isNotNull();

		}
		logger.info("allAccounts >>>>>");
	}

	@Test
	public void allOwnersWithUsers() {
		logger.info("<<<<< allOwnersWithUsers ");
		var owners = ownerRepository.findAll();
		assertThat(owners).size().isEqualTo(3);
		for(var owner:owners) {
			var users = owner.getUsers();
			assertThat(users).size().isEqualTo(2);
		}
		logger.info("allOwnersWithUsers >>>>>");
	}

	@Test
	public void allUsers() {
		logger.info("<<<<< allUsers ");
		var users = userRepository.findAll();
		assertThat(users).size().isEqualTo(4);
		for(var user:users) {
			assertThat(user.getOwners()).isNotNull();
		}
		logger.info("allUsers >>>>>");
	}

	@Test
	public void posts() {
		logger.info("<<<<< posts ");
		var posts = postRepository.findAll();
		assertThat(posts).size().isEqualTo(0);
		var owner = ownerRepository.findOwnerByName("group1");
		var account0 = accountRepository.findByIbanAndAccountType(ibans.get(0), AccountEntity.AccountType.BANK);
		var account1 = accountRepository.findByIbanAndAccountType(ibans.get(1), AccountEntity.AccountType.BANK);
		assertThat(account0).isPresent();
		assertThat(account1).isPresent();
		assertThat(owner).isPresent();
		var post = postRepository.save(
				PostEntity.builder()
						.date(Calendar.getInstance().getTime())
						.fromAccount(account0.get())
						.toAccount(account1.get())
						.amount(BigDecimal.ONE)
						.build());
		assertThat(post).hasFieldOrProperty("id");
		post = postRepository.save(
				PostEntity.builder()
						.date(Calendar.getInstance().getTime())
						.fromAccount(account0.get())
						.toAccount(account1.get())
						.amount(BigDecimal.ONE)
						.build());
		assertThat(post).hasFieldOrProperty("id");

		assertThat(balance.balance(account0.get())).isEqualByComparingTo(BigDecimal.TWO.negate());
		assertThat(balance.balance(account1.get())).isEqualByComparingTo(BigDecimal.TWO);
		assertThat(balance.balance(account0.get())).isEqualByComparingTo(balance.balance_slow(account0.get()));

		logger.info("post >>>>>");
	}

	@Test
	public void deposits() {
		logger.info("<<<<< deposits ");
		logger.info("");
		var owner = ownerRepository.findOwnerByName("group1");
		var account0 = accountRepository.findByIbanAndAccountType(ibans.get(0), AccountEntity.AccountType.BANK);
		var account1 = accountRepository.findByIbanAndAccountType(ibans.get(1), AccountEntity.AccountType.BANK);
		assertThat(account0).isPresent();
		assertThat(account1).isPresent();
		assertThat(owner).isPresent();
		var post1 = postRepository.save(
				PostEntity.builder()
						.date(Calendar.getInstance().getTime())
						.fromAccount(account0.get())
						.toAccount(account1.get())
						.amount(BigDecimal.ONE)
						.build());
		assertThat(post1).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");
		var post2 = postRepository.save(
				PostEntity.builder()
						.date(Calendar.getInstance().getTime())
						.fromAccount(account0.get())
						.toAccount(account1.get())
						.amount(BigDecimal.ONE)
						.build());
		assertThat(post2).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");
		var post3 = postRepository.save(
				PostEntity.builder()
						.date(Calendar.getInstance().getTime())
						.fromAccount(account0.get())
						.toAccount(account1.get())
						.amount(BigDecimal.ONE)
						.build());
		assertThat(post3).hasFieldOrProperty("id").hasNoNullFieldsOrPropertiesExcept("deposit");

		assertThat(balance.balance(account0.get())).isEqualByComparingTo(BigDecimal.valueOf(3).negate());
		assertThat(balance.balance(account1.get())).isEqualByComparingTo(BigDecimal.valueOf(3));

		// deposit
		var startDate = Calendar.getInstance();
		var endDate = Calendar.getInstance();
		endDate.add(Calendar.YEAR,1);

		var tag1 = tagRepository.save(TagEntity.builder()
						.name("tag 1")
						.deposits(new HashSet<DepositEntity>())
				.build());
		assertThat(tag1).isNotNull().hasFieldOrPropertyWithValue("id", 1L);
		var tag2 = tagRepository.save(TagEntity.builder()
				.name("tag 2")
				.deposits(new HashSet<DepositEntity>())
				.build());
		assertThat(tag2).isNotNull().hasFieldOrPropertyWithValue("id", 2L);
		var tag3 = tagRepository.save(TagEntity.builder()
				.name("tag 3")
				.deposits(new HashSet<DepositEntity>())
				.build());
		assertThat(tag3).isNotNull().hasFieldOrPropertyWithValue("id", 3L);
		var interest = interestRepository.save(
						FlatInterestEntity.builder()
						.begin(startDate.getTime())
						.annualRate(BigDecimal.valueOf(0.025))
						.finish(endDate.getTime()).build());
		assertThat(interest).isNotNull().hasFieldOrPropertyWithValue("id", 1L);
		var deposit1 = depositRepository
									.save(
										DepositEntity.builder()
										.interest( interest )
										.begin(startDate.getTime())
										.due(endDate.getTime())
										.belongsTo(owner.get())
										.name("test deposit with flat interest of 2.5% over 2 years")
										.account(account0.get())
										.posts(Set.of(post1, post2))
										.tags(new HashSet<TagEntity>())
										.build().addTag(tag1).addTag(tag2));
		assertThat(deposit1).isNotNull().hasFieldOrPropertyWithValue("id", 1L);
		var deposit2 = depositRepository
				.save(
						DepositEntity.builder()
								.interest( interest )
								.begin(startDate.getTime())
								.due(endDate.getTime())
								.belongsTo(owner.get())
								.name("test deposit2 with flat interest of 2.5% over 2 years")
								.account(account0.get())
								.posts(Set.of(post3))
								.tags(new HashSet<TagEntity>())
								.build().addTag(tag2).addTag(tag3));
		assertThat(deposit1).isNotNull().hasFieldOrPropertyWithValue("id", 1L);

		// test find all deposits to a tag
		var depositsForTag3 = depositRepository.findByTag(tag2);
		assertThat(depositsForTag3).size().isEqualTo(2);

		// TODO test calc total amount of a deposit consisting of several posts
		var totalAmountOfDeposit1 = depositRepository.totalAmountOf(deposit1);
		assertThat(totalAmountOfDeposit1).hasValue(BigDecimal.valueOf(2));

		// TODO test find all deposits for an account

		// TODO check incosistency: deposit posting not with the deposit account as destination account of posting

		logger.info("deposits >>>>>");
	}


}
