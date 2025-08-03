package rsh.web.account;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.AccountsBaseData;
import rsh.domain.account.deposit.DepositRepository;
import rsh.domain.account.post.PostRepository;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserEntity;
import rsh.user.UserService;
import rsh.web.base.ErrorsViewModel;

import java.util.*;

@Controller
@SessionAttributes("challenge")
public class AccountController extends ControllerBase {
    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class AccountDialogStateViewModel {
        public enum DialogMode{CLOSED, ADD,EDIT}
        @Builder.Default
        private Boolean dialogOpen = Boolean.FALSE;
        @Builder.Default
        private AccountDialogStateViewModel.DialogMode dialogMode = DialogMode.CLOSED;
        @Builder.Default
        private Boolean hideActions = Boolean.FALSE;
    }
    @Autowired
    AccountRepository accountRepository;
    @Autowired
    OwnerRepository ownerRepository;
    @Autowired
    UserService userService;

    @Autowired
    MessageSource messageSource;
    @Autowired
    private PostRepository postRepository;
    @Autowired
    private DepositRepository depositRepository;

    @ModelAttribute("username")
    public String username() {
        var user  = getUser();
        return user.getUsername();
    }

    @ModelAttribute("allAccountTypes")
    public List<AccountEntity.AccountType> allAccountTypes() {
        return Arrays.asList(AccountEntity.AccountType.values());
    }

    @ModelAttribute("accounts")
    public List<AccountsBaseData> getModelAttributeAllAccounts() {
        var user =  getUser();
        var accounts =  accountRepository.findBaseWithBalanceByUser(UserEntity.builder().id(user.getId()).build());
        return accounts;
    }

    @ModelAttribute("usersOwnerEntities")
    public List<OwnerEntity> getUseresOwnerEntities() {
        var user = getUser();
        var owners = ownerRepository.findOwnerByUser(UserEntity.builder().id(user.getId()).build());
        return owners;
    }

    @GetMapping("/accounts")
    public String getAccounts(@ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel,
                              @ModelAttribute("accountDialogState") final AccountDialogStateViewModel dialogState,
                              @ModelAttribute("accountViewModel") final AccountViewModel accountViewModel) {
        accountViewModel.setDateCreated(Calendar.getInstance().getTime());
        accountViewModel.setDateClosed(Calendar.getInstance().getTime());
        dialogState.setDialogOpen(false);
        dialogState.setDialogMode(AccountDialogStateViewModel.DialogMode.CLOSED);
        return "accounts";
    }

    @PostMapping(path = "/accounts/add")
    @Modifying
    public String postAdd( @Valid @ModelAttribute("accountViewModel") final AccountViewModel accountViewModel
                         , BindingResult bindingResult
                         , @ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel
                         , @ModelAttribute("accountDialogState") final AccountDialogStateViewModel dialogState
                         ) {
            if (bindingResult.hasErrors()) {
                dialogState.setDialogOpen(true);
                dialogState.setDialogMode(AccountDialogStateViewModel.DialogMode.ADD);
                bindingResultToError(bindingResult, errorsViewModel);
                return "accounts";
            }
            dialogState.setDialogOpen(true);
            dialogState.setDialogMode(AccountDialogStateViewModel.DialogMode.CLOSED);
            var ownerEntityId = accountViewModel.getOwnerEntityId();
            assert(ownerEntityId != null);
            var maybeOwner = ownerRepository.findById(ownerEntityId); // ownerEntity should be cached
            assert(maybeOwner.isPresent());
            var newAccountsId = saveNewAndReturnId(
                    maybeOwner.get(),
                    accountViewModel.getAccountType(),
                    accountViewModel.getName(),
                    accountViewModel.getIban(),
                    accountViewModel.getBank(),
                    accountViewModel.getDateCreated(),
                    accountViewModel.getDateClosed());
            return "redirect:/accounts";
        }

        @GetMapping("/accounts/edit/{id}")
        public String getAccountEdit(
                           @PathVariable("id") Long accountId
                         , @ModelAttribute("accountViewModel") final AccountViewModel accountViewModel
                         , BindingResult bindingResult
                         , @ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel
                         , @ModelAttribute("accountDialogState") final AccountDialogStateViewModel dialogState
        ) {
            errorsViewModel.clear();
            return accountRepository.findById(accountId)
                            .map(accountEntity -> {
                                initAccountViewModelFromEntity(accountViewModel, accountEntity);
                                dialogState.setDialogOpen(Boolean.TRUE);
                                dialogState.setDialogMode(AccountDialogStateViewModel.DialogMode.EDIT);
                                return "accounts";
                            }).orElseGet(() ->{
                                errorsViewModel.getMessages().add("errors.message.generic");
                                return "accounts";
                            });
        }

        @PostMapping("/accounts/edit/{id}")
        @Modifying
        public String postAccountEdit(
                @PathVariable("id") Long accountId
                , @ModelAttribute("accountViewModel") final AccountViewModel accountViewModel
                , BindingResult bindingResult
                , @ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel
                , @ModelAttribute("accountDialogState") final AccountDialogStateViewModel dialogState
        ) {
            if (bindingResult.hasErrors()) {
                //dialogState.setDialogOpen(true);
                //dialogState.setDialogMode(AccountDialogStateViewModel.DialogMode.EDIT);
                bindingResultToError(bindingResult, errorsViewModel);
                return "accounts";
            }
            var ownerEntityId = accountViewModel.getOwnerEntityId();
            assert(ownerEntityId != null);
            var maybeOwner = ownerRepository.findById(ownerEntityId); // ownerEntity should be cached
            assert(maybeOwner.isPresent());
            var maybeAccountEntity = accountRepository.findById(accountViewModel.getId());
            return maybeAccountEntity.map(accountEntity -> {
                        accountEntity.setBelongsTo(maybeOwner.get());
                        accountEntity.setAccountType(accountViewModel.getAccountType());
                        accountEntity.setName(accountViewModel.getName());
                        accountEntity.setIban(accountViewModel.getIban());
                        accountEntity.setBank(accountViewModel.getBank());
                        accountEntity.setDateCreated(accountViewModel.getDateCreated());
                        accountEntity.setDateClosed(accountViewModel.getDateClosed());
                        accountRepository.save(accountEntity);
                        return "redirect:/accounts";
                    }).orElseGet(() -> {
                        return "accounts";
                    });
        }

    @DeleteMapping("/accounts/{aid}")
    @Transactional
    @Modifying
    public ResponseEntity<Void> removeGroup(@PathVariable("aid") Long aid,
                                            @ModelAttribute("accountDialogState") final AccountController.AccountDialogStateViewModel accountStateViewModel,
                                            @ModelAttribute("vwerrors") ErrorsViewModel errorsViewModel) {
        var user = getUser();
        try {
            var accountEntity = accountRepository.findById(aid).orElseThrow();
            // check if user is an owner, if not then forbidden
            if(!ownerRepository.findOwnerByUser(UserEntity.builder().id(user.getId()).build()).contains(accountEntity.getBelongsTo())) {
                throw new RuntimeException(String.format("ALERT: user %s tried to delete an account %s not beeing an owner.", user.getUsername(), accountEntity.getName()));
            }
            // check if there are still posts aviailable, if so, forbidden
            if(postRepository.countPostsByFromAccount(accountEntity) != 0 ||
                    postRepository.countPostsByToAccount(accountEntity) != 0) {
                throw new RuntimeException(String.format("ALERT: user %s tried to delete an account %s but there are still postings referring to this account.", user.getUsername(), accountEntity.getName()));
            }

            // check if there are still deposits refering this account, if so, forbidden
            if(depositRepository.countDepositsByAccount(accountEntity) != 0) {
                throw new RuntimeException(String.format("ALERT: user %s tried to delete an account %s but there are still depostits referring to this account.", user.getUsername(), accountEntity.getName()));
            }

            accountRepository.delete(accountEntity);
        } catch (Exception e) {
            System.err.println(e);
            errorsViewModel.setMessages(List.of("errors.message.generic"));
            return ResponseEntity.status(401).build();
        } finally {
            return ResponseEntity.noContent().build();
        }
    }

        void initAccountViewModelFromEntity(AccountViewModel accountViewModel, AccountEntity accountEntity) {
            accountViewModel.setId(accountEntity.getId());
            accountViewModel.setAccountType(accountEntity.getAccountType());
            accountViewModel.setName(accountEntity.getName());
            accountViewModel.setBank(accountEntity.getBank());
            accountViewModel.setIban(accountEntity.getIban());
            accountViewModel.setOwnerEntityId(accountEntity.getBelongsTo().getId());
            accountViewModel.setDateClosed(accountEntity.getDateClosed());
            accountViewModel.setDateCreated(accountEntity.getDateCreated());
        }
        Long saveNewAndReturnId(OwnerEntity ownerEntity, AccountEntity.AccountType accountType, String name, String iban, String bank, Date dateCreated, Date dateClosed) {
            var accountEntity = new AccountEntity();
            accountEntity.setBelongsTo(ownerEntity);
            accountEntity.setAccountType(accountType);
            accountEntity.setName(name);
            accountEntity.setBank(bank);
            accountEntity.setIban(iban);
            accountEntity.setDateCreated(dateCreated);
            accountEntity.setDateClosed(dateClosed);
            return accountRepository.save(accountEntity).getId();
        }
}