package rsh.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.post.PostEntity;
import rsh.domain.account.post.PostRepository;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserBaseDto;
import rsh.user.UserEntity;
import rsh.user.UserRepository;
import rsh.user.UserService;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

@org.springframework.web.bind.annotation.RestController
@Profile("devel") // set spring.profiles.active=test in properties or commandline arg.
public class TestEnvRestController {
        @Autowired
        AccountRepository accountRepository;
        @Autowired
        PostRepository postRepository;
        @Autowired
        UserRepository userRepository;
        @Autowired
        UserService userService;
        @Autowired
        OwnerRepository ownerRepository;

        @GetMapping("/api/self/details")
        public UserEntity getAccounts() {
                var me = getUserEntity();
                return me;
        }
        protected UserEntity getUserEntity() {
                var auth = SecurityContextHolder.getContext().getAuthentication();
                var user = (UserBaseDto)auth.getPrincipal();// ugly upcast, so is the framework
                var userName = user.getUsername();
                var maybeRegisteredUser = userRepository.findUserByUsername(userName);
                if (maybeRegisteredUser.isEmpty()) {
                        throw new UsernameNotFoundException("User not found.");
                } else {
                        return maybeRegisteredUser.get();
                }
        }

        @GetMapping("/api/generate")
        public String generate() {
                generateOwnersUsersAccountsAndPosts();
                return "Some Testdata generated";
        }

        private void generateOwnersUsersAccountsAndPosts() {
                var owners = List.of("group1", "group2", "group3")
                                .stream().map(n -> generateOwner(n)).toList();
                var users = List.of("u1", "u2", "u3", "u4", "u5")
                        .stream().map(u->generateUser(u)).toList();
                owners.forEach(o -> sample(users, 2).forEach(u->o.addUser(u)) );
                Arrays.stream(AccountEntity.AccountType.values()).map(
                        accountType -> {
                                String countryCode = "DE";
                                String bban = IBANGenerator.generateGermanBBAN();
                                String iban = IBANGenerator.generateIBAN(countryCode, bban);
                                var owner = owners.get(0);
                                return AccountEntity.builder()
                                        .accountType(accountType)
                                        .bank("Bank:" + accountType.name())
                                        .belongsTo(owner)
                                        .iban(iban)
                                        .dateCreated(Calendar.getInstance().getTime())
                                        .bank("BANK " + accountType.name())
                                        .name("ACCOUNT " + accountType.name())
                                        .build();
                        }
                ).map(a -> {
                        return accountRepository.save(a);
                }).forEach(a -> {
                        var fromAccount
                                = accountRepository
                                        .findByUser(getUserEntity())
                                        .stream()
                                        .filter(fa -> fa.getAccountType() == AccountEntity.AccountType.BANK)
                                        .findFirst()
                                        .orElseThrow();
                        var post = PostEntity.builder()
                                .amount(BigDecimal.TEN)
                                .fromAccount(fromAccount)
                                .toAccount(a)
                                .date(Calendar.getInstance().getTime())
                                .build();
                        postRepository.save(post);
                });
                ;
        }

        private UserEntity generateUser(String name) {
                var user = UserEntity.builder()
                        .id(name)
                        .email(name + "@example.com")
                        .username(name)
                        .owners(new HashSet<>())
                        .build();
                return userRepository.save(user);
        }
        private OwnerEntity generateOwner(String name) {
                var auth = SecurityContextHolder.getContext().getAuthentication();
                var userDetails = auth.getPrincipal();
                // TODO see MyAuthenticationToken class, getPricipal return String, maybe it shoould return as UserDetail object.
                //      like this:
                //      var userName = ((UserDetails) userDetails).getUsername(); // ugly upcast, so is the framework
                var userName = ((String) userDetails); // ugly upcast, so is the framework
                var maybeRegisteredUser = userRepository.findUserByUsername(userName);
                if (maybeRegisteredUser.isEmpty()) {
                        throw new UsernameNotFoundException("User not found.");
                } else {
                        var user =  maybeRegisteredUser.get();
                        var owner = ownerRepository.save(
                                OwnerEntity.builder()
                                        .name(name)
                                        .admin(user)
                                        .users(new HashSet<>()).build()
                                        .addUser(user));
                        return owner;
                }
        }

        private<T> List<T> sample(List<T> wholeList, int sampleSize) {
                List<T> copy = new ArrayList<>(wholeList);
                Collections.shuffle(copy);
                List<T> sample = copy.subList(0, sampleSize);
                return sample;
        }
}


class IBANGenerator {

        private static final SecureRandom random = new SecureRandom();

        // Generate a random numeric string of specified length
        private static String generateRandomDigits(int length) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < length; i++) {
                        sb.append(random.nextInt(10));
                }
                return sb.toString();
        }

        // Generate German BBAN: 8 digits for bank code + 10 digits for account number
        public static String generateGermanBBAN() {
                String bankCode = generateRandomDigits(8);
                String accountNumber = String.format("%010d", Math.abs(random.nextLong()) % 1_000_000_0000L);
                return bankCode + accountNumber;
        }

        public static String generateIBAN(String countryCode, String bban) {
                String tempIban = bban + countryCode + "00";
                StringBuilder numericIBAN = new StringBuilder();

                // Convert letters to numbers (A=10, B=11, ..., Z=35)
                for (char ch : tempIban.toCharArray()) {
                        if (Character.isLetter(ch)) {
                                numericIBAN.append(ch - 'A' + 10);
                        } else {
                                numericIBAN.append(ch);
                        }
                }

                BigInteger num = new BigInteger(numericIBAN.toString());
                int checksum = 98 - num.mod(BigInteger.valueOf(97)).intValue();
                return countryCode + String.format("%02d", checksum) + bban;
        }

        public static void main(String[] args) {
                String countryCode = "DE";
                String bban = generateGermanBBAN();
                String iban = generateIBAN(countryCode, bban);
                System.out.println("Generated IBAN: " + iban);
        }
        private UserBaseDto getUserEntity() {
                var auth = SecurityContextHolder.getContext().getAuthentication();
                var user = (UserBaseDto)auth.getPrincipal();
                if (user == null) {
                        throw new UsernameNotFoundException("User not found.");
                } else {
                        return user;
                }
        }
}

