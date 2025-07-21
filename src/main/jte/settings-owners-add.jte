@import gg.jte.support.ForSupport
@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.user.UserBaseDto
@import rsh.web.SettingsController
@import rsh.web.SettingsController.OwnerWithUserIds
@import java.util.ArrayList
@import java.util.List
@param JteLocalizer localizer
@param CsrfToken csrf
@param List<UserBaseDto> users
@param SettingsController.OwnerWithUserIds editOwner = null
@param SettingsController.SettingsDialogStateViewModel settingsDialogState
@param rsh.web.ErrorsViewModel vwerrors

@if(editOwner == null)
    !{editOwner = OwnerWithUserIds.builder().build();}
@endif

<!-- Modal Edit/Add Dialog -->
<%-- <dialog id="modal-dialog" open="${enabled}"> --%>
<dialog id="modal-dialog" open="${settingsDialogState.getDialogMode() != SettingsController.SettingsDialogStateViewModel.DialogMode.NONE}">
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
              action="/settings/owners"
              method="post">

            @if(csrf != null)
                <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
            @endif

            <input type="hidden" readonly id="oid" name="oid" value="${editOwner.getOid()}"/>

            <label for="name">${localizer.localize("settings.owner.name")}</label>
            <input type="text" id="name" name="name" value="${editOwner.getName()}" required />
            @template.fieldErrors(fieldName = "name", vwerrors = vwerrors, localizer = localizer)

            @template.settings-owners-assign-users(localizer = localizer,
                                                    users = users,
                                                    editOwner = editOwner,
                                                    vwerrors = vwerrors)

            <footer>
                <div role="group">
                    <button id="btnCancelOwner"
                            role="button"
                            type="reset"
                            class="secondary"
                            data-target="modal-dialog"
                            onclick="toggleModal(event)">
                        ${localizer.localize("button.text.cancel")}
                    </button>
                    <button autofocus
                            id="btnSubmitOwner"
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
