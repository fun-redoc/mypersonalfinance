@import rsh.conf.JteLocalizer
@import rsh.domain.owner.OwnerEntity
@import rsh.user.UserBaseDto
@import rsh.web.*
@import rsh.web.JteControllerAdvice
@import java.util.AbstractList
@import java.util.List
@param JteLocalizer localizer
@param String username
@param List<UserBaseDto> allUsers
@param List<OwnerEntity> allOwnersForUser
@param List<OwnerEntity> allOwnersUserIsAdmin
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
                                  name = username,
                                  users = allUsers,
                                  allOwnersForUser = allOwnersForUser,
                                  allOwnersUserIsAdmin = allOwnersUserIsAdmin,
                                  enabled = true,
                                  vwerrors = vwerrors )

        <%--
        <article>
            <header th:text="#{settings.article.header.api.key}"></header>
            <input id="inpApiKey"
                   type="text"
                   th:placeholder="#{settings.article.api.key.input.placeholder}"
            />
            <footer >
                <div role="group">
                    <button id="btnApiKey"
                            role="button"
                            class="primary"
                            type="button"
                            th:text="#{settings.article.api.key.button.save.in.browser}">
                        create api key
                    </button>
                </div>
            </footer>
            <script language="JavaScript">
                const btnApiKey = document.getElementById('btnApiKey');
                btnApiKey.addEventListener('click', function() {
                    const inpApiKey = document.getElementById('inpApiKey');
                    localStorage.setItem("api.key." + inpKeyPasswd.dataset.username, inpApiKey.value);
                });
            </script>
        </article>
        --%>
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
                       `
)

