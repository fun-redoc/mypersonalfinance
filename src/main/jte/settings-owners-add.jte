@import gg.jte.support.ForSupport
@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.owner.OwnerEntity
@import rsh.user.UserBaseDto
@import rsh.user.UserEntity
@import rsh.web.DialogStateViewModel
@import java.util.List
@import java.util.Optional
@param JteLocalizer localizer
@param CsrfToken csrf
@param String name = null
@param List<UserBaseDto> users
@param boolean enabled = true
@param rsh.web.ErrorsViewModel vwerrors


<!-- Modal Edit/Add Dialog -->
<dialog id="modal-dialog" open="${enabled}">
    <article>
        <header>
            <button
                    aria-label="Close"
                    rel="prev"
                    data-target="modal-dialog"
                    onclick="toggleModal(event)"
            ></button>
            <h2>${localizer.localize("settings.owners.title.edit")}</h2>
        </header>

        <form id="formOwner"
              action="/settings/owners/save"
              method="post">

            @if(csrf != null)
                <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
            @endif

            <label for="name">${localizer.localize("settings.owner.name")}</label>
            <input type="text" id="name" name="name" value="${name}" required />
            @template.fieldErrors(fieldName = "name", vwerrors = vwerrors, localizer = localizer)

            @template.settings-owners-assign-users(localizer = localizer, users = users, vwerrors = vwerrors)

            <footer>
                <div role="group">
                    <button id="btnCancel"
                            role="button"
                            type="reset"
                            class="secondary"
                            data-target="modal-dialog"
                            onclick="toggleModal(event)">
                        ${localizer.localize("button.text.cancel")}
                    </button>
                    <button autofocus
                            id="btnSubmit"
                            type="button"
                            role="button"
                            class="primary">
                        ${localizer.localize("button.text.submit")}
                    </button>
                </div>
            </footer>
        </form>
    </article>
</dialog>
