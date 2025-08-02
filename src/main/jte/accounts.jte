@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.account.AccountEntity
@import rsh.domain.account.AccountsBaseData
@import rsh.domain.owner.OwnerEntity
@import rsh.web.AccountController
@import rsh.web.AccountViewModel
@import rsh.web.JteControllerAdvice
@import java.text.SimpleDateFormat
@import java.util.List
@import java.util.Optional
@param CsrfToken csrf
@param JteLocalizer localizer
@param String username
@param List<AccountsBaseData> accounts
@param List<AccountEntity.AccountType> allAccountTypes
@param List<OwnerEntity> usersOwnerEntities
@param AccountController.AccountDialogStateViewModel accountDialogState
@param AccountViewModel accountViewModel
@param rsh.web.ErrorsViewModel vwerrors

!{SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");}

!{var pageContent = @`
    <%-- TODO display general vwerrors --%>
    <!-- modal key entry if not provided in settings -->
    <dialog id="keyEntry" >
<%--        <article th:replace="settings.html::enckey(false)"></article> --%>
        @template.settings-enckey(localizer = localizer, name = username, enabled = true, vwerrors = vwerrors)
    </dialog>
    <!-- Modal Edit/Add Dialog -->
    <dialog id="modal-example" open="${accountDialogState.getDialogOpen()}">
        <article>
            <header>
                <button
                        aria-label="Close"
                        rel="prev"
                        data-target="modal-example"
                        onclick="toggleModal(event)"
                ></button>
                !{var formAction = "";}
                @if(accountDialogState.getDialogMode() == AccountController.AccountDialogStateViewModel.DialogMode.EDIT)
                    <h2>${localizer.localize("accounts.account.title.edit")}</h2>
                    !{formAction = "/accounts/edit/" + accountViewModel.getId();}
                @elseif(accountDialogState.getDialogMode() == AccountController.AccountDialogStateViewModel.DialogMode.ADD)
                    <h2>${localizer.localize("accounts.account.title.add")}</h2>
                    !{formAction = "/accounts/add";}
                @elseif(accountDialogState.getDialogMode() == AccountController.AccountDialogStateViewModel.DialogMode.CLOSED)
                    <h2>${localizer.localize("accounts.account.title.add")}</h2>
                    !{formAction = "/accounts/add";}
                @else
                    ${Optional.empty().orElseThrow(() -> new RuntimeException("TODO unexpected dialog state")).toString()}
                   <%-- // TODO unexpected state crash to error page --%>
                @endif
            </header>

            <form id="formAccount"
                  action="${formAction}"
                  method="post">
                
                @if(csrf != null)
                    <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
                @endif

                <label for="name">${localizer.localize("accounts.account.name")}</label>
                <input type="text" id="name" name="name" value="${accountViewModel.getName()}" required />
                @template.fieldErrors(fieldName = "name", vwerrors = vwerrors, localizer = localizer)

                <fieldset>
                    <legend>${localizer.localize("accounts.account.type")}</legend>
                    @for(var accountType:allAccountTypes)
                        <span>
                            <label for="id${accountType}">${localizer.localize(String.format("account.type.%s",accountType.name()))}</label>
                            @if(accountType.equals(accountViewModel.getAccountType()))
                                <input checked id="id${accountType}" type="radio" name="accountType" value="${accountType}"  />
                            @else
                                <input id="id${accountType}" type="radio" name="accountType" value="${accountType}"  />
                            @endif
                            <span>&nbsp;</span>
                        </span>
                    @endfor
                </fieldset>
                @template.fieldErrors(fieldName = "accountType", vwerrors = vwerrors, localizer = localizer)

                <%-- Owner --%>
                <select id="owner-entity-id" name="ownerEntityId" aria-label="Select your the appropriate group." required>
                    @if(accountViewModel.getOwnerEntityId() == null)
                        <option selected disabled value="">
                            ${localizer.localize("accounts.account.select.group")}
                        </option>
                    @else
                        <option disabled value="">
                            ${localizer.localize("accounts.account.select.group")}
                        </option>
                    @endif
                    @for(var owner:usersOwnerEntities)
                        @if(owner.getId() == accountViewModel.getOwnerEntityId())
                            <option selected value="${owner.getId()}">${owner.getName()}</option>
                        @else
                            <option value="${owner.getId()}">${owner.getName()}</option>
                        @endif
                    @endfor
                </select>
                @template.fieldErrors(fieldName = "ownerEntityId", vwerrors = vwerrors, localizer = localizer)

                <label for="bank">${localizer.localize("accounts.account.bank")}</label>
                <input type="text" id="bank" name="bank" value="${accountViewModel.getBank()}" />
                @template.fieldErrors(fieldName = "bank", vwerrors = vwerrors, localizer = localizer)

                <label for="iban"> ${localizer.localize("accounts.account.iban")}</label>
                <input type="text" id="iban" name="iban"  data-encrypted="${accountViewModel.getIban()}"
                       pattern="[a-zA-Z][a-zA-Z]\s?\d\d\s?\d\d\d\d\s?\d\d\d\d\s?\d\d\d\d\s?\d\d\d\d\s?\d\d"
                       placeholder="XY 11 2222 3333 4444 5555 66"/>
                @template.fieldErrors(fieldName = "iban", vwerrors = vwerrors, localizer = localizer)

                <div class="grid">
                    <div>
                        <label for="creation-date">${localizer.localize("accounts.account.creation.date")}</label>
                        <input type="date" id="creation-date" name="dateCreated" value="${formatter.format(accountViewModel.getDateCreated())}"/>
                        @template.fieldErrors(fieldName = "'dateCreated'", vwerrors = vwerrors, localizer = localizer)
                    </div>
                    <div >
                        <label for="close-date">${localizer.localize("accounts.account.close.date")}</label>
                        <input type="date" id="close-date" name="dateClosed" value='${accountViewModel.getDateClosed() == null ? "": formatter.format(accountViewModel.getDateClosed())}'/>
                        @template.fieldErrors(fieldName = "'dateClosed'", vwerrors = vwerrors, localizer = localizer)
                    </div>
                </div>

                <footer>
                    <div role="group">
                        <button id="btnCancel"
                                role="button"
                                type="reset"
                                class="secondary"
                                data-target="modal-example"
                                onclick="toggleModal(event)">
                            ${localizer.localize("button.text.cancel")}
                        </button>
                        <button autofocus
                                id="btnSubmitAccount"
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
    <!-- ./ Modal Edit/Add Dialog -->
    @template.generalErrors(vwerrors = vwerrors)
    <!-- List of Accounts -->
    @if(accounts.isEmpty())
        <h2>${localizer.localize("accounts.empty")}</h2>
        <button id="btnOpenNewAccountModal"
                data-target="modal-example"
        >${localizer.localize("accounts.btn.open.new.account.modal")}</button>
    @else
        <section>
            <h2>${localizer.localize("accounts.my_accounts")}</h2>
            <button id="btnOpenNewAccountModal"
                    data-target="modal-example"
            >${localizer.localize("accounts.btn.open.new.account.modal")}</button>
            <table>
                <thead>
                <tr>
                    <th>${localizer.localize("accounts.account.id")}</th>
                    <th>${localizer.localize("accounts.account.type")}</th>
                    <th>${localizer.localize("accounts.account.name")}</th>
                    <th>${localizer.localize("accounts.account.balance")}</th>
                    @if(!accountDialogState.getHideActions())
                        <th>${localizer.localize("accounts.account.actions")}</th>
                    @endif
                </tr>
                </thead>
                <tbody>
                @for(var account:accounts)
                    <tr>
                        <td>${account.getId()}</td>
                        <td>${account.getAccountType()}</td>
                        <td>${account.getName()}</td>
                        <td>${account.getKred().subtract(account.getDeb())}</td>
                        @if(!accountDialogState.getHideActions())
                            <td>
                                <a href="/accounts/edit/${account.getId()}"   >${localizer.localize("button.text.edit")}</a>
                                <a href="#" onclick='deleteAccount(event, "${csrf.getToken()}", ${account.getId()})'  class="secondary">${localizer.localize("button.text.delete")}</a>
                            </td>
                        @endif
                    </tr>
                @endfor
                </tbody>
            </table>
        </section>
    @endif
`;}

@template.layout(
    localizer =localizer,
    currentMenu = JteControllerAdvice.MenuItem.ACOOUNTS,
    page = localizer.localize("accounts.page"),
    content = pageContent,
    additional_head = @`
                            <script src="/security.js" ></script>
                            <script src="/accounts.js" ></script>
                        `
)

<%--
<script language="JavaScript">
    document.getElementById('btnOpenNewAccountModal')
            .addEventListener('click', (evt) => {
                console.log("btnOpenNewAccountModal:click");
              // TODO I'm accessing element IDs from the fragment of settings.html here, not the most nice ways, but
    //          //      move the fragment to fragments.html for more transparency
    //          const form = document.getElementById('formAccount');
    //          //const username = document.getElementById('inpKeyPasswd').dataset.username
    //          //const storageKey = 'enc.key.' + username;
    //          //const password = sessionStorage.getItem(storageKey); // TODO find a more secure way to temporarilly save the encryption key,
    //          //                                                     // this is only for convenience, to avoid that the user has to type in the
    //          //                                                     // everey time he accesses an accounts encrypted data
    //          const password = getEncKey();
    //          if(password) {
    //            form.reset();
    //            toggleModal(evt);
    //          } else {
    //              const keyEntryDialog = document.getElementById('keyEntry');
    //              const btnCreateKey = document.getElementById('btnCreateKey');
    //              btnCreateKey.addEventListener('click', async () => {
    //                  const that = this;
    //                    btnCreateKey.removeEventListener('click', that);
    //                    closeModal(keyEntryDialog);
    //                    form.reset();
    //                    toggleModal(evt);
    //              });
    //              openModal(keyEntryDialog);
    //          }
            });
</script>
--%>