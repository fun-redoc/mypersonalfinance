package rsh.web;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.AccountService;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserService;

import java.security.Principal;
import java.util.*;

@Controller
@SessionAttributes("challenge")
public class AccountController {
    @Autowired
    AccountRepository accountRepository;
    @Autowired
    AccountService accountService;
    @Autowired
    OwnerRepository ownerRepository;
    @Autowired
    UserService userService;

    @Autowired
    MessageSource messageSource;

    @ModelAttribute("username")
    public String username() {
        var user  = userService.getUserEntity();
        return user.getUsername();
    }

    @ModelAttribute("allAccountTypes")
    public List<AccountEntity.AccountType> allAccountTypes() {
        return Arrays.asList(AccountEntity.AccountType.values());
    }

    @ModelAttribute("accounts")
    public List<AccountRepository.AccountsBaseData> getModelAttributeAllAccounts() {
        var user =  userService.getUserEntity();
        var accounts =  accountRepository.findBaseWithBalanceByUser(user);
        return accounts;
    }

    @ModelAttribute("usersOwnerEntities")
    public List<OwnerEntity> getUseresOwnerEntities() {
        var user = userService.getUserEntity();
        var owners = ownerRepository.findOwnerByUser(user);
        return owners;
    }

    @GetMapping("/accounts")
    public String getAccounts(@ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel,
                              @ModelAttribute("dialogState") final DialogStateViewModel dialogState,
                              @ModelAttribute("accountViewModel") final AccountViewModel accountViewModel) {
        accountViewModel.setDateCreated(Calendar.getInstance().getTime());
        accountViewModel.setDateClosed(Calendar.getInstance().getTime());
        dialogState.setDialogOpen(false);
        dialogState.setDialogMode(DialogStateViewModel.DialogMode.CLOSED);
        return "accounts";
    }

    @PostMapping(path = "/accounts/add")
//    @ResponseStatus(HttpStatus.CREATED)
    public String postAdd( @Valid @ModelAttribute("accountViewModel") final AccountViewModel accountViewModel
                         , BindingResult bindingResult
                         , @ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel
                         , @ModelAttribute("dialogState") final DialogStateViewModel dialogState
                         ) {
            if (bindingResult.hasErrors()) {
                //TODO transfer binding errors to vwerrors
                dialogState.setDialogOpen(true);
                dialogState.setDialogMode(DialogStateViewModel.DialogMode.ADD);
                for(var bindingError:bindingResult.getFieldErrors()) {
                    if(!errorsViewModel.getFieldMessages().containsKey(bindingError.getField())) {
                        errorsViewModel.getFieldMessages().put(bindingError.getField(),new ArrayList<>());
                    }
                    var fieldMessages = errorsViewModel.getFieldMessages().get(bindingError.getField());
                    fieldMessages.add(bindingError.getDefaultMessage());
                }
                return "accounts";
            }
            dialogState.setDialogOpen(true);
            dialogState.setDialogMode(DialogStateViewModel.DialogMode.CLOSED);
            var ownerEntityId = accountViewModel.getOwnerEntityId();
            assert(ownerEntityId != null);
            var maybeOwner = ownerRepository.findById(ownerEntityId); // ownerEntity should be cached
            assert(maybeOwner.isPresent());
            var newAccountsId = accountService.saveNewAndReturnId(
                    maybeOwner.get(),
                    accountViewModel.getAccountType(),
                    accountViewModel.getName(),
                    accountViewModel.getIban(),
                    accountViewModel.getBank(),
                    accountViewModel.getDateCreated(),
                    accountViewModel.getDateClosed());
            return "redirect:/accounts";
        }

}