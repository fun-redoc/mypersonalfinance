@param String id
@param rsh.conf.JteLocalizer localizer
@param java.util.List<rsh.domain.account.deposit.DepositRepository.AccountListDTO> allAccounts
@param Long accountId

<select id="${id}"
        required
        name="accountId"
        aria-label='${localizer.localize("accounts.dropdown.aria.label.select.account")}'
    >
    <option selected value="">${localizer.localize("accounts.dialog.select.account")}</option>
    @for(var ac:allAccounts)
        <option value='${ac.id()}' selected="${accountId != null && accountId == ac.id()}">
            @if(ac.bank() != null)
                ${ac.name()}: ${localizer.localize("account.at.bank")} ${ac.bank()}
            @else
                ${ac.name()}: ${localizer.localize("account.at.bank")} ${localizer.localize("account.bank.n.a")}
            @endif
        </option>
    @endfor
</select>