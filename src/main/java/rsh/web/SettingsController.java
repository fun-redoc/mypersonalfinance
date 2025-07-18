package rsh.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.owner.OwnerRepository;
import rsh.user.UserBaseDto;
import rsh.user.UserEntity;
import rsh.user.UserRepository;
import rsh.user.UserService;

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

    public record OwnerWithUserIds(@NotNull(message = "settings.owners.add.no.name.error")
                                   @NotBlank(message = "settings.owners.add.no.name.error") String name,
                                   List<String> userIds) {
        public OwnerWithUserIds {
            if(userIds == null) {
                userIds = List.of();
            }
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

    @PostMapping("/owners")
    public String saveOwnerWithUsers(@Valid @ModelAttribute("owner") final OwnerWithUserIds owner,
                                     final BindingResult bindingResult,
                                     @ModelAttribute("settingsDialogState") final SettingsDialogStateViewModel dialogStateViewModel,
                                     @ModelAttribute("vwerrors") ErrorsViewModel errorsViewModel) {
        if (bindingResult.hasErrors()) {
            dialogStateViewModel.setDialogMode(SettingsDialogStateViewModel.DialogMode.OWNER_ADD);
            bindingResultToError(bindingResult, errorsViewModel);
            return "settings";
        }
        var ownerEntity = OwnerEntity.builder()
                .name(owner.name())
                .admin(UserEntity.builder().id(getUser().getId()).build())
                .users(owner.userIds().stream().map(uid -> UserEntity.builder().id(uid).build()).collect(Collectors.toSet()))
                .build();
        ownerRepository.save(ownerEntity);
        return  "redirect:/settings";
    }

}