package rsh.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import rsh.domain.account.AccountEntity;

import java.util.List;

@RestController
public class AccountRestController {
    @GetMapping("/api/accounts")
    public List<AccountEntity> getAccounts() {
       return List.of();
    }
}
