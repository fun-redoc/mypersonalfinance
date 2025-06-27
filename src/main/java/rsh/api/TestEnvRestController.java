package rsh.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.owner.OwnerEntity;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.util.Arrays;
import java.util.HashSet;

@org.springframework.web.bind.annotation.RestController
@Profile("test") // set spring.profiles.active=test in properties or commandline arg.
public class TestEnvRestController {
        @Autowired
        AccountRepository accountRepository;

        @GetMapping("/api/generate")
        public String generate() {
        //        var accounts =
        //        Arrays.stream(AccountEntity.AccountType.values()).map(
        //                accountType -> {
        //                        AccountEntity.builder()
        //                                .accountType(accountType)
        //                                .bank("Bank:" + accountType.name())
        //                                .belongsTo()
        //                }
        //        )

            return "Some Testdata generated";
        }

//        private generateOwner() {
//
//                var auth = SecurityContextHolder.getContext().getAuthentication();
//                var userDetails = auth.getPrincipal();
//                // TODO see MyAuthenticationToken class, getPricipal return String, maybe it shoould return as UserDetail object.
//                //      like this:
//                //      var userName = ((UserDetails) userDetails).getUsername(); // ugly upcast, so is the framework
//                var userName = ((String) userDetails); // ugly upcast, so is the framework
//                var maybeRegisteredUser = userRepository.findUserByUsername(userName);
//                if (maybeRegisteredUser.isEmpty()) {
//                        throw new UsernameNotFoundException("User not found.");
//                } else {
//                        return maybeRegisteredUser.get();
//                }
//                var group1 = ownerRepository.save(OwnerEntity.builder().name("group1").users(new HashSet<>()).build().addUser(u1).addUser(u2));
//        }
}
