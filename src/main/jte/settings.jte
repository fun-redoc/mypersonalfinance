@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.owner.OwnerEntity
@import rsh.user.UserBaseDto
@import rsh.web.*
@import rsh.web.JteControllerAdvice
@import java.util.List
@import java.util.Optional
@param JteLocalizer localizer
@param CsrfToken csrf
@param String username
@param List<UserBaseDto> allUsers
@param List<OwnerEntity> allOwnersForUser
@param List<OwnerEntity> allOwnersUserIsAdmin
@param SettingsController.OwnerWithUserIds owner = null
@param SettingsController.SettingsDialogStateViewModel settingsDialogState
@param rsh.web.ErrorsViewModel vwerrors


!{var pageContent = @`

<main class="container-fluid">

    @template.generalErrors(vwerrors = vwerrors)

    <div class="grid">
        @template.settings-enckey(localizer = localizer,
                                  name = username,
                                  enabled = true,
                                  vwerrors = vwerrors )
        @template.settings-owners(localizer = localizer,
                                  csrf = csrf,
                                  name = username,
                                  users = allUsers,
                                  editOwner = owner,
                                  allOwnersForUser = allOwnersForUser,
                                  allOwnersUserIsAdmin = allOwnersUserIsAdmin,
                                  enabled = true,
                                  settingsDialogState = settingsDialogState,
                                  vwerrors = vwerrors )

    </div>
</main>
`;}

@template.layout(
    localizer =localizer,
    currentMenu = JteControllerAdvice.MenuItem.SETTINGS,
    page = localizer.localize("settings.page"),
    content = pageContent,
    additional_head = @`
                            <script src="/security.js" ></script>
                            <script src="/settings-owners.js" ></script>
                            <script src="/settings-owners-add.js" ></script>
                       `
)

