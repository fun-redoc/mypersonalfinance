package rsh.domain.account;

import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Date;

@Service
public class AccountService {
    AccountRepository accountRepository;

    public AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    public AccountEntity save(Long userId, AccountEntity.AccountType accountType, String name, String iban, String bank, Date dateCreated, Date dateClosed) {
        var accountEntity = new AccountEntity();
        // TODO var userEntity = getUserEntity();
        //assert(userEntity != null);
        //accountEntity.setBelongsTo(userEntity);
        accountEntity.setAccountType(accountType);
        accountEntity.setName(name);
        accountEntity.setBank(bank);
        accountEntity.setIban(iban);
        accountEntity.setDateCreated(dateCreated);
        accountEntity.setDateClosed(dateClosed);
        return accountRepository.save(accountEntity);
    }

}
