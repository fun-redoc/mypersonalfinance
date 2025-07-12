@import gg.jte.support.ForSupport
@import rsh.conf.JteLocalizer
@import rsh.domain.owner.OwnerEntity
@import rsh.user.UserBaseDto
@import rsh.user.UserEntity
@import java.util.List
@param JteLocalizer localizer
@param String name
@param List<UserBaseDto> users
@param List<OwnerEntity> allOwnersForUser
@param List<OwnerEntity> allOwnersUserIsAdmin
@param boolean enabled = true
@param rsh.web.ErrorsViewModel vwerrors


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
            <button id="btnSaveGroups"
                    role="button"
                    class="primary"
                    type="button">
                    ${localizer.localize("settings.article.groups.button.save")}
            </button>
        </div>
    </footer>
    <script language="JavaScript" >
        // TODO by the rules, no fragments out side fragmens.html and no inline script...fix this
        const btnSaveGroups = document.getElementById('btnSaveGroups');
        btnSaveGroups.addEventListener('click', function() {
            console.log("btnCreateKey click");
            console.log("btnCreateKey click unimplemented");
            // TODO implement this
        });
    </script>
</article>