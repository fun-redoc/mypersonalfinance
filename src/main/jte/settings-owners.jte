@import gg.jte.support.ForSupport
@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.owner.OwnerEntity
@import rsh.user.UserBaseDto
@import rsh.web.SettingsController
@import java.util.List
@param JteLocalizer localizer
@param CsrfToken csrf
@param String name
@param List<UserBaseDto> users
@param SettingsController.OwnerWithUserIds editOwner = null 
@param List<OwnerEntity> allOwnersForUser
@param List<OwnerEntity> allOwnersUserIsAdmin
@param boolean enabled = true
@param SettingsController.SettingsDialogStateViewModel settingsDialogState
@param rsh.web.ErrorsViewModel vwerrors

@template.settings-owners-add(localizer = localizer,
                                csrf = csrf,
                                users = users,
                                editOwner = editOwner,
                                settingsDialogState = settingsDialogState,
                                vwerrors = vwerrors)

@template.generalErrors(vwerrors = vwerrors)

<article hidden="${!enabled}">
    <header>${localizer.localize("settings.article.header.owners")}</header>

    <%-- content --%>
    <label for="adminOwnersList">${localizer.localize("settings.article.caption.adminOwners")}</label>
    <div id="adminOwnersList">
            @for(var ownerWithForSupport : ForSupport.of(allOwnersUserIsAdmin))
                @if(ownerWithForSupport.isFirst())
                    <details name="owners" open>
                @else
                    <details name="owners">
                @endif
                        <summary>${ownerWithForSupport.get().getName()}</summary>
                        <p>
                            @if(ownerWithForSupport.get().getUsers().size() == 0)
                                <em>${localizer.localize("settings.owners.no.users")}</em>
                                <a href="/settings/owners/${ownerWithForSupport.get().getId()}">
                                   ${localizer.localize("settings.article.groups.button.edit.group")}
                                </a>
                                &nbsp;
                                <a href="#"
                                   onclick="removeGroup(event, ${ownerWithForSupport.get().getId()})"a>
                                    ${localizer.localize("settings.article.groups.button.remove.group")}
                                </a>
                            @else
                            <table>
                                <thead>
                                <tr>
                                    <th scope="col">${localizer.localize("settings.article.caption.username")}</th>
                                    <th scope="col">${localizer.localize("settings.article.caption.email")}</th>
                                    <th scope="col">${localizer.localize("settings.article.owners.action")}</th>
                                </tr>
                                </thead>
                                <tbody>
                                @for(var user:ownerWithForSupport.get().getUsers())
                                    <tr>
                                        <th scope="row">${user.getUsername()}</th>
                                        <td>${user.getEmail()}</td>
                                        <td>
                                            <a href="#"
                                               onclick='removeUserFromOwner(event, "${csrf.getToken()}", "${user.getId()}", ${ownerWithForSupport.get().getId()})'
                                            >${localizer.localize("settings.article.owners.remove.user")}
                                            </a>
                                        </td>
                                    </tr>
                                @endfor
                                </tbody>
                                <tfoot>
                                <tr>
                                    <th scope="row">&nbsp;</th>
                                    <td colspan="2" style="text-align: right;">
                                        <a href="/settings/owners/${ownerWithForSupport.get().getId()}">
                                            ${localizer.localize("settings.article.groups.button.edit.group")}
                                        </a>
                                    </td>
                                </tr>
                                </tfoot>
                            </table>
                        @endif
                        </p>
                        @if(!ownerWithForSupport.isLast())
                            <hr/>
                        @endif
                @if(ownerWithForSupport.isFirst())
                    </details>
                @else
                    </details>
                @endif
            @endfor
    </div>

    <footer >
        <div role="group">
            <button id="btnAddGroup"
                    role="button"
                    class="primary"
                    type="button"
                    data-target="modal-dialog"
                    onclick="toggleModal(event)">
                    ${localizer.localize("settings.article.groups.button.add.group")}
            </button>
        </div>
    </footer>
</article>