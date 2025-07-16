@import gg.jte.support.ForSupport
@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.owner.OwnerEntity
@import rsh.user.UserBaseDto
@import rsh.user.UserEntity
@import java.util.List
@param JteLocalizer localizer
@param CsrfToken csrf
@param String name
@param List<UserBaseDto> users
@param List<OwnerEntity> allOwnersForUser
@param List<OwnerEntity> allOwnersUserIsAdmin
@param boolean enabled = true
@param rsh.web.ErrorsViewModel vwerrors

@template.settings-owners-add(localizer = localizer,
                                csrf = csrf,
                                users = users,
                                enabled = false,
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
                                        <td> TODO remove</td>
                                    </tr>
                                @endfor
                                </tbody>
                                <tfoot>
                                <tr>
                                    <th scope="row">TODO</th>
                                    <td>${localizer.localize("settings.article.owners.add.user")}</td>
                                    <td>${localizer.localize("settings.article.owners.add.user")}</td>
                                </tr>
                                </tfoot>
                            </table>
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
                    data-target="modal-dialog">
                    ${localizer.localize("settings.article.groups.button.add.group")}
            </button>
        </div>
    </footer>
    <script language="JavaScript" >
        const btnAddGroup = document.getElementById('btnAddGroup');
        btnAddGroup
          .addEventListener('click', (evt) => {
                console.log("btnAddGroup click");
              //form.reset();
              toggleModal(evt);
          });
    </script>
</article>