package rsh.domain.account;

import org.springframework.stereotype.Service;

// TODO remove class
@Service
public class OBSOLETE_AccountService {
    AccountRepository accountRepository;

    public OBSOLETE_AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

//    public Long saveNewAndReturnId(OwnerEntity ownerEntity, AccountEntity.AccountType accountType, String name, String iban, String bank, Date dateCreated, Date dateClosed) {
//        var accountEntity = new AccountEntity();
//        accountEntity.setBelongsTo(ownerEntity);
//        accountEntity.setAccountType(accountType);
//        accountEntity.setName(name);
//        accountEntity.setBank(bank);
//        accountEntity.setIban(iban);
//        accountEntity.setDateCreated(dateCreated);
//        accountEntity.setDateClosed(dateClosed);
//        return accountRepository.save(accountEntity).getId();
//    }

}
