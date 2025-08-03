package rsh.web.settings;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserBaseDto;
import rsh.user.UserEntity;
import rsh.user.UserRepository;
import rsh.user.UserService;
import rsh.web.account.ControllerBase;
import rsh.web.base.ErrorsViewModel;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@SessionAttributes("challenge")
@RequestMapping("/settings")
public class SettingsController extends ControllerBase {
    @Data
    @AllArgsConstructor
    public static class SettingsDialogStateViewModel {
       public enum DialogMode{NONE, OWNER_ADD}
       private SettingsDialogStateViewModel.DialogMode dialogMode;
    }
    @Autowired
    UserRepository userRepository;
    @Autowired
    UserService userService;
    @Autowired
    OwnerRepository ownerRepository;

    @Autowired
    MessageSource messageSource;

    //@Autowired
    //JteLocalizer localizer;
    @Autowired
    TransactionTemplate transactionTemplate;

    @ModelAttribute("username")
    public String username() {
        return getUser().getUsername();
    }

    @ModelAttribute("allUsers")
    public List<UserBaseDto> allUsers() {
        var allUsers = userRepository.findAllUsersWithBaseDto();
        return allUsers;
    }

    @ModelAttribute("allOwnersForUser")
    public List<OwnerEntity> allOwnersForUser() {
        var user = getUser();
        var owners = ownerRepository.findOwnerByUser(UserEntity.builder().id(user.getId()).build());
        return owners;
    }

    @ModelAttribute("allOwnersUserIsAdmin")
    public List<OwnerEntity> allOwnersUserIsAdmin() {
        var user = getUser();
        var owners = ownerRepository.findOwnersByAdminFetchingUsers(UserEntity.builder().id(user.getId()).build());
        return owners;
    }

    @Data
    @Builder
    @AllArgsConstructor
    public static class OwnerWithUserIds{
        Long oid; // presence signals that this object is already persisted
        @NotNull(message = "settings.owners.add.no.name.error")
        @NotBlank(message = "settings.owners.add.no.name.error") String name;
        List<String> userIds;
        public OwnerWithUserIds() {
            this.userIds = new ArrayList<>();
            this.oid = null;
        }
    };

    @GetMapping
    public String getSettings(
            @ModelAttribute("owner") final OwnerWithUserIds owner,
            @ModelAttribute("settingsDialogState") final SettingsDialogStateViewModel dialogStateViewModel,
            @ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel) {
        dialogStateViewModel.setDialogMode(SettingsDialogStateViewModel.DialogMode.NONE);
        return "settings";
    }

    //@GetMapping("/owners")
    //public String getSettingsOwnersAdd(
    //        @ModelAttribute("settingsDialogState") final SettingsDialogStateViewModel dialogStateViewModel,
    //        @ModelAttribute("vwerrors") final ErrorsViewModel errorsViewModel) {
    //    dialogStateViewModel.setDialogMode(SettingsDialogStateViewModel.DialogMode.OWNER_ADD);
    //    return "settings";
    //}

    //@ExceptionHandler(value = {DataIntegrityViolationException.class})
    //public ResponseEntity<String> handlePreconditionFailed(DataIntegrityViolationException exception) {
    //    System.err.println(exception);
    //    return ResponseEntity.status(HttpStatus.CONFLICT).build();
    //}
    //@ExceptionHandler(value = {DataIntegrityViolationException.class})
    //public ModelAndView handlePreconditionFailed(HttpServletRequest req,
    //                                             DataIntegrityViolationException exception
    //                                             ) {
    //    System.err.println(exception);
    //    var mav = new ModelAndView();
    //    mav.setViewName("settings");
    //    mav.addObject("localizer", localizer);
    //    mav.addObject("vwerrors", new ErrorsViewModel());
    //    mav.addObject("settingsDialogState", new SettingsDialogStateViewModel(SettingsDialogStateViewModel.DialogMode.OWNER_ADD));

    //    return mav;
    //}

    @PostMapping("/owners")
    //@Transactional // in case of DB Errors such as data integrity error etc. the annotation seems barly usable
    @Modifying
    public String saveOwnerWithUsers(@Valid @ModelAttribute("owner") final OwnerWithUserIds owner,
                                     final BindingResult bindingResult,
                                     @ModelAttribute("settingsDialogState") final SettingsDialogStateViewModel dialogStateViewModel,
                                     @ModelAttribute("vwerrors") ErrorsViewModel errorsViewModel) {
        if (bindingResult.hasErrors()) {
            dialogStateViewModel.setDialogMode(SettingsDialogStateViewModel.DialogMode.OWNER_ADD);
            bindingResultToError(bindingResult, errorsViewModel);
            return "settings";
        }
        try {
            var retval = transactionTemplate.execute(status -> {
                if(owner.oid == null) {
                    var ownerEntity = OwnerEntity.builder()
                            .name(owner.getName())
                            .admin(UserEntity.builder().id(getUser().getId()).build())
                            .users(owner.getUserIds().stream().map(uid -> UserEntity.builder().id(uid).build()).collect(Collectors.toSet()))
                            .build();
                    ownerRepository.save(ownerEntity);
                } else {
                    try {
                        var ownerEntity = ownerRepository.findOwnerByIdFetchingUsers(owner.oid).orElseThrow();
                        if(!ownerEntity.getName().equals(owner.getName())) {
                            ownerEntity.setName(owner.getName());
                        }
                        for(var uid:owner.getUserIds()) {
                            if(!ownerEntity.getUsers().contains(UserEntity.builder().id(uid).build())) {
                                // add this user as userEntity
                                var userEntity = userRepository.findById(uid).orElseThrow();
                                ownerEntity.addUser(userEntity);
                            }
                        }
                        for(var userEntity:ownerEntity.getUsers()) {
                            if(!owner.getUserIds().contains(userEntity.getId())) {
                                // remove this userEntity
                                ownerEntity.getUsers().remove(userEntity);
                                userEntity.getOwners().remove(ownerEntity);
                            }
                        }
                        ownerRepository.save(ownerEntity);
                    } catch (Exception e) {
                        System.err.println(e);
                        errorsViewModel.setMessages(List.of("errors.message.generic"));
                    }
                }
                return  "redirect:/settings";
            });
            return retval;
        } catch (DataIntegrityViolationException e) {
            System.err.println(e);
            errorsViewModel.setMessages(List.of("settings.owners.add.error.alreay.exists"));
            return "settings";
        } catch (Exception e) {
            System.err.println(e);
            errorsViewModel.setMessages(List.of("errors.message.generic"));
            return "settings";
        }
    }

    @DeleteMapping("/owners/{oid}")
    @Transactional
    @Modifying
    public ResponseEntity<Void> removeGroup(@PathVariable("oid") Long oid,
                                            @ModelAttribute("settingsDialogState") final SettingsDialogStateViewModel dialogStateViewModel,
                                            @ModelAttribute("vwerrors") ErrorsViewModel errorsViewModel) {
        System.out.println("----------------- remove  owner -------------------");
        var user = getUser();
        try {
            var ownerEntity = ownerRepository.findById(oid).orElseThrow();
            if(!ownerEntity.getAdmin().getId().equals(user.getId())) {
                throw new RuntimeException(String.format("ALERT: user %s tried to delete the group %s not beeing the group admin.", user.getUsername(), ownerEntity.getName()));
            }
            ownerRepository.delete(ownerEntity);
        } catch (Exception e) {
            System.err.println(e);
            errorsViewModel.setMessages(List.of("errors.message.generic"));
            return ResponseEntity.status(401).build();
        } finally {
            return ResponseEntity.noContent().build();
        }
    }

    @DeleteMapping("/owners/{oid}/users/{uid}")
    @Transactional
    @Modifying
    public ResponseEntity<Void> removeUserFromOwner(@PathVariable("oid") Long oid,
                                              @PathVariable("uid") String uid,
                                              @ModelAttribute("settingsDialogState") final SettingsDialogStateViewModel dialogStateViewModel,
                                              @ModelAttribute("vwerrors") ErrorsViewModel errorsViewModel) {
        System.out.println("----------------- remove user from owner -------------------");
        var user = getUser();
        try {
            var ownerEntity = ownerRepository.findById(oid).orElseThrow();
            var removeUserEntity = userRepository.findById(uid).orElseThrow();
            ownerEntity.getUsers().remove(removeUserEntity);
            removeUserEntity.getOwners().remove(ownerEntity);
            ownerRepository.save(ownerEntity);
        } catch (Exception e) {
            System.err.println(e);
            errorsViewModel.setMessages(List.of("errors.message.generic"));
        } finally {
            return ResponseEntity.noContent().build();
        }
    }

    @GetMapping("/owners/{oid}")
    public String getOwnerForEdditing(@PathVariable("oid") final Long oid,
                                      @ModelAttribute("owner") final OwnerWithUserIds owner,
                                      @ModelAttribute("settingsDialogState") final SettingsDialogStateViewModel dialogStateViewModel,
                                      @ModelAttribute("vwerrors") ErrorsViewModel errorsViewModel) {
        try {
            var ownerEntity = ownerRepository.findById(oid).orElseThrow();
            owner.setName(ownerEntity.getName());
            owner.setOid(oid);
            owner.getUserIds().addAll(ownerEntity.getUsers().stream().map(u->u.getId()).toList());
            dialogStateViewModel.setDialogMode(SettingsDialogStateViewModel.DialogMode.OWNER_ADD);
        } catch (Exception e) {
            System.err.println(e);
            errorsViewModel.setMessages(List.of("errors.message.generic"));
        }
        return "settings";
    }

}