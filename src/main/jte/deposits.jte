@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.account.deposit.DepositDto
@import rsh.domain.account.deposit.DepositListDto
@import rsh.domain.account.deposit.DepositRepository
@import rsh.domain.account.deposit.InterestEntity
@import rsh.web.base.ErrorsViewModel
@import rsh.web.deposit.DepositController
@import rsh.web.auth.JteControllerAdvice
@import rsh.web.base.NullTollerantDateFormatter
@import java.text.SimpleDateFormat
@import java.util.Date
@import java.util.List
@param CsrfToken csrf
@param JteLocalizer localizer
@param String username
@param Date today
@param List<DepositListDto> allDeposits
@param List<DepositRepository.AccountListDTO> allAccounts
@param List<InterestEntity.InterestType> allInterestTypes
@param DepositDto deposit
@param DepositController.DepositPageStatus viewStatus
@param ErrorsViewModel vwerrors

!{NullTollerantDateFormatter formatter = new NullTollerantDateFormatter(new SimpleDateFormat("yyyy-MM-dd"));}

!{var pageContent = @`

    @template.deposits_new( csrf = csrf,
                            localizer = localizer,
                            formatter = formatter ,
                            deposit = deposit,
                            username = username ,
                            today = today,
                            allAccounts = allAccounts,
                            allInterestTypes = allInterestTypes,
                            viewStatus = viewStatus,
                            vwerrors = vwerrors)
    @template.generalErrors(vwerrors = vwerrors)
        <div role="group">
            <h2>${localizer.localize("deposits.my_deposits")}</h2>
            <div class="centered">
                <label for="chkShowOnlyCurrent">${localizer.localize("deposits.filter.current")}</label>
                <input type="checkbox" id="chkShowOnlyCurrent" name="chkShowOnlyCurrent" role="switch" >
            </div>

            <button id="btnNewDeposit" data-target="modalEditAddDialog">
                    ${localizer.localize("deposits.btn.new.deposit")}
            </button>
            <!--              onclick="toggleModal(event)" -->
        </div>


        <!-- List of Deposits -->
        <%-- @if(!allDeposits.isEmpty()) --%>
        <section>
            <table id="deposits-table">
                <thead>
                <tr>
                    <th>${localizer.localize("deposits.list.name")}</th>
                    <th>${localizer.localize("deposits.list.bank")}</th>
                    <th class="sortable" data-key='end-date' data-type='date'>
                        ${localizer.localize("deposits.list.end")}
                    </th>
                    <th class="sortable" data-key='amount' data-type='number'>
                        ${localizer.localize("deposits.list.amount")}
                    </th>
                    <th class="sortable" data-key='interest' data-type='number'>
                        ${localizer.localize("deposits.list.interest")}
                    </th>
                    @if(!viewStatus.isHideActions())
                    <th>
                        ${localizer.localize("accounts.account.actions")}
                    </th>
                    @endif
                </tr>
                </thead>
                <tbody>
                @for(var deposit:allDeposits)
                    <tr class="deposit-row"
                        data-iscurrent="${deposit.getBegin().before(today) && today.before(deposit.getEnd())}"
                        data-start="${formatter.format(deposit.getBegin())}"
                        data-end="${formatter.format(deposit.getEnd())}"
                        data-today="${formatter.format(today)}"
                    >
                        <td>${deposit.getName()}</td>
                        <td>${deposit.getBank()}</td>
                        <td data-key='end-date' data-value="${formatter.format(deposit.getEnd())}">
                            ${formatter.format(deposit.getEnd())}
                        </td>
                        <td data-key='amount' data-value="${deposit.getAmount()}">
                            ${deposit.getAmount()}
                        </td>
                        <td data-key='interest' data-value="${deposit.getEffectiveInterest()}">
                            ${deposit.getEffectiveInterest()}
                        </td>
                        @if(!viewStatus.isHideActions())
                        <td>
                            <a href="/deposits/edit/${deposit.getId()}" role="link">${localizer.localize("button.text.edit")}</a>
                            <a href="/deposits/delete/${deposit.getId()}"
                               role="link"
                               class="secondary">
                               ${localizer.localize("button.text.delete")}
                            </a>
                        </td>
                        @endif
                    </tr>
                @endfor
                </tbody>
            </table>
        </section>
        <%-- @endif --%>
`;}

@template.layout(
localizer =localizer,
currentMenu = JteControllerAdvice.MenuItem.DEPOSITS,
page = localizer.localize("deposits.page"),
content = pageContent,
additional_head = @`
    <script src="/security.js" ></script>
    <script src="/deposits.js" ></script>
    <script src="/deposits_new.js" ></script>
`
)
