package rsh.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.AccountsBaseData;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserBaseDto;
import rsh.user.UserEntity;
import rsh.user.UserRepository;

import java.util.List;

@org.springframework.web.bind.annotation.RestController
public class RestController {
    @Autowired
    UserRepository userRepository;
    @Autowired
    OwnerRepository ownerRepository;
    @Autowired
    AccountRepository accountRepository;

    @GetMapping("/api/accounts")
    public List<AccountsBaseData> allAccountsUserOwns() {
        //var owners = ownerRepository.findOwnerByUser(getUserEntity());
        var accounts = accountRepository.findBaseByUser(getUserEntity());
        return accounts;
    }

    protected UserEntity getUserEntity() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        var user = (UserBaseDto)auth.getPrincipal();
        var userName = user.getUsername();
        // TODO for sake of security, avoid loading whole entity, check existence of the username by specialized query
        var maybeRegisteredUser = userRepository.findUserByUsername(userName);
        if (maybeRegisteredUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found.");
        } else {
            return maybeRegisteredUser.get();
        }
    }

}
