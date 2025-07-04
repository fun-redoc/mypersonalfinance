package rsh.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;

@org.springframework.web.bind.annotation.RestController
@Profile("devel") // set spring.profiles.active=test in properties or commandline arg.
public class TestEnvRestController {
        @Autowired
        AccountRepository accountRepository;
        @Autowired
        UserRepository userRepository;
        @Autowired
        OwnerRepository ownerRepository;

        @GetMapping("/api/self/details")
        public UserEntity getAccounts() {
                var me = getUserEntity();
                return me;
        }
        protected UserEntity getUserEntity() {
                var auth = SecurityContextHolder.getContext().getAuthentication();
                var userDetails = auth.getPrincipal();
                var userName = ((UserDetails) userDetails).getUsername(); // ugly upcast, so is the framework
                //var userName = ((String) userDetails); // ugly upcast, so is the framework
                var maybeRegisteredUser = userRepository.findUserByUsername(userName);
                if (maybeRegisteredUser.isEmpty()) {
                        throw new UsernameNotFoundException("User not found.");
                } else {
                        return maybeRegisteredUser.get();
                }
        }

        @GetMapping("/api/generate")
        public String generate() {
                var owners = List.of("group1", "group2", "group3")
                                .stream().map(n -> generateOwner(n)).toList();
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
                ).forEach(a -> {
                        accountRepository.save(a);
                });

            return "Some Testdata generated";
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
                                        .users(new HashSet<>()).build()
                                        .addUser(user));
                        return owner;
                }
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
}

