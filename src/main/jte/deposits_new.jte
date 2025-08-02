@import gg.jte.support.ForSupport
@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.domain.account.deposit.DepositDto
@import rsh.domain.account.deposit.DepositRepository
@import rsh.domain.account.deposit.InterestEntity
@import rsh.web.DepositController
@import rsh.web.NullTollerantDateFormatter
@import java.util.Date
@import java.util.List
@import java.util.Optional
@param CsrfToken csrf
@param JteLocalizer localizer
@param NullTollerantDateFormatter formatter
@param DepositDto deposit
@param String username
@param Date today
@param List<DepositRepository.AccountListDTO> allAccounts
@param List<InterestEntity.InterestType> allInterestTypes
@param DepositController.DepositPageStatus viewStatus
@param rsh.web.ErrorsViewModel vwerrors

<dialog id="keyEntry" >
    <%--        <article th:replace="settings.html::enckey(false)"></article> --%>
    @template.settings-enckey(localizer = localizer, name = username, enabled = true, vwerrors = vwerrors)
</dialog>
<!-- Modal Edit/Add Dialog -->
<dialog id="modal-example" open="${viewStatus.isDialogOpen()}">
    <article>
        <header>
            <button
                    aria-label="Close"
                    rel="prev"
                    data-target="modal-example"
                    onclick="toggleModal(event)"
            ></button>
                !{var formAction = "";}
                @if(viewStatus.getDialogMode() == DepositController.DepositPageStatus.DialogMode.EDIT)
                    <h2 id="topOfModalDialog">${localizer.localize("deposits.title.edit")}</h2>
                    !{formAction = "/deposits/edit/" + deposit.getId();}
                @elseif(viewStatus.getDialogMode() == DepositController.DepositPageStatus.DialogMode.NEW)
                    <h2 id="topOfModalDialog">${localizer.localize("deposits.title.add")}</h2>
                    !{formAction = "/deposits/add";}
                @elseif(viewStatus.getDialogMode() == DepositController.DepositPageStatus.DialogMode.CLOSED)
                    <h2 id="topOfModalDialog">${localizer.localize("deposits.title.add")}</h2>
                    !{formAction = "/deposits/add";}
                @else
                    ${Optional.empty().orElseThrow(() -> new RuntimeException("TODO unexpected dialog state")).toString()}
                   <%-- // TODO unexpected state Intentionall crash to error page --%>
                @endif
        </header>

        <form id="formAddDeposits"
              action="${formAction}"
              method="post">
            @if(csrf != null)
                <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}"/>
            @endif


            <label for="tags">${localizer.localize("new_deposit.tags")}</label>
            <fieldset role="group" id="tags" class="tags">
                @if(deposit.getTags() != null)
                    @for(var tag:deposit.getTags())
                      <span class="tag"
                            data-id="${tag.getId()}" data-name="${tag.getName()}">
                            ${tag.getName()}
                      </span>
                    @endfor
                @endif
                <input id="tagInput" type="text" value="" placeholder='${localizer.localize("new_deposit.placeholder.add.tag")}' />
            </fieldset>
            <p></p>

            <label for="deposit_name">${localizer.localize("new_deposit.name")}</label>
            <input id="deposit_name" type="text" name="name" value="${deposit.getName()}" placeholder='${localizer.localize("new_deposit.placeholder.add.name")}'/>
            @template.fieldErrors(fieldName = "name", vwerrors = vwerrors, localizer = localizer)

            <!-- accounts dropdown -->
            <legend>${localizer.localize("new_deposit.account")}</legend>
            @template.accounts_dropdown(id = "idAccounts",
                                        localizer = localizer,
                                        allAccounts = allAccounts,
                                        accountId = deposit.getAccountId())

            <label for="beginDate">${localizer.localize("new_deposit.begin.date")}</label>
            <input type="date" id="beginDate" name="begin" value="${formatter.format(deposit.getBegin())}"/>

            <label for="endDate">${localizer.localize("new_deposit.end.date")}</label>
            <input type="date" id="endDate" name="finish" value="${formatter.format(deposit.getFinish())}"/>

            <!-- interest -->
            <legend>${localizer.localize("new_deposit.interest.type")}</legend>
            <select id="selectInterest" name="interestType" aria-label='${localizer.localize("deposits_new.select.interest.kind")}' required>
                <option selected disabled value="">
                    ${localizer.localize("new_deposit.interest.type")}
                </option>
                @for(var interest:allInterestTypes)
                    <option value="${interest}"
                            selected='${deposit.getInterestType() != null && deposit.getInterestType().equals(interest)}'
                    >
                        ${localizer.localize(String.format("interest.type.%s",interest))}
                    </option>
                @endfor
            </select>
            @template.fieldErrors(fieldName = "interestType", vwerrors = vwerrors, localizer = localizer)

            <div>
                @if(deposit.getInterestType() != null && deposit.getInterestType().equals(InterestEntity.InterestType.ZERO))
                    <div>
                        <p>${localizer.localize("interest.type.ZERO")}</p>
                    </div>
                @elseif(deposit.getInterestType() != null && deposit.getInterestType().equals(InterestEntity.InterestType.FLAT))
                    <div >
                        <label for="annualRate">${localizer.localize("new_deposit.interest.rate")}</label>
                        <input type="number" inputmode="decimal" min="0.01" step="0.01" id="annualRate"
                               name="flatInterest.annualRate"
                               value="${deposit.getFlatInterest().getAnnualRate()}"/>
                        @template.fieldErrors(fieldName = "flatInterest.annualRate", vwerrors = vwerrors, localizer = localizer)
                    </div>
                @elseif(deposit.getInterestType() != null && deposit.getInterestType().equals(InterestEntity.InterestType.FLAT_END_BONUS))
                    <div>
                        <label for="annualRate1">${localizer.localize("new_deposit.interest.rate")}</label>
                        <input type="number"  inputmode="decimal" min="0.01" step="0.01" id="annualRate1"
                               name="bonusInterest.annualRate"
                               value="${deposit.getBonusInterest().getAnnualRate()}"/>
                        @template.fieldErrors(fieldName = "bonusInterest.annualRate", vwerrors = vwerrors, localizer = localizer)

                        <label for="finalBonusRate">${localizer.localize("new_deposit.interest.bonus")}</label>
                        <input type="number" inputmode="decimal" min="0.01" step="0.01" id="finalBonusRate"
                               name="bonusInterest.finalBonusRate"
                               value="${deposit.getBonusInterest().getFinalBonusRate()}"
                        />
                        @template.fieldErrors(fieldName = "bonusInterest.finalBonusRate", vwerrors = vwerrors, localizer = localizer)
                    </div>
                @else
                    <div>
                        <p>${localizer.localize("interest.type.ZERO")}</p>
                    </div>
                @endif
            </div>

            <!-- postings -->
            @if(deposit.getAccountId()!=null)
            <div>
                <legend>${localizer.localize("new_deposit.postings.title")}</legend>
                <table>
                    <thead>
                    <tr>
                        <th hidden="true"></th>
                        <th>${localizer.localize("new_deposit.postings.col.nr")}</th>
                        <th>${localizer.localize("new_deposit.postings.col.date")}</th>
                        <th>${localizer.localize("new_deposit.postings.col.amount")}</th>
                        <th>${localizer.localize("new_deposit.postings.col.action")}</th>
                    </tr>
                    </thead>
                    <tbody>
                    @if(deposit.getAssignedPostings() != null && deposit.getAssignedPostings().size() > 0)
                    @for(var assignedPostings:ForSupport.of(deposit.getAssignedPostings()))
                        !{var p = assignedPostings.get();}
                        !{var i = assignedPostings.getIndex();}
                        <tr>
                            <td hidden="true"> <!-- cummulates already existing postings for the post action-->
                                <input type="hidden"
                                       name='assignedPostings[${i}].id'
                                       value="${p.getId()}"
                                />
                                <input type="hidden"
                                       name='assignedPostings[${i}].date'
                                       value='${formatter.format(p.getDate())}'
                                />
                                <input type="hidden"
                                       name='assignedPostings[${i}].amount'
                                       value="${p.getAmount()}"
                                />
                            </td>
                            <td>${i+1}</td>
                            <td>${formatter.format(p.getDate())}</td>
                            <td>${p.getAmount()}</td>
                            <td>
                                <button id="btnRemovePosting" name="remove_posting" type="submit"
                                        class="removePosting"
                                        data-id="${p.getId()}">
                                        ${localizer.localize("new_deposit.postings.remove")}
                                </button>
                            </td>
                        </tr>
                    @endfor
                    @endif
                    @if(deposit.getFreePostings() != null && deposit.getFreePostings().size() > 0)
                    <tr>
                        <td colspan="3">
                            <select id="selectPosting"
                                    name="addPostingId"
                                    value="${deposit.getAddPostingId()}"
                                    aria-label='${localizer.localize("new_deposit.aria.label.select.Posting")}' >
                                <option selected value="">
                                        ${localizer.localize("new_deposit.posting.add.select.caption")}
                                </option>
                                @for(var freePosting:ForSupport.of(deposit.getFreePostings()))
                                    !{var p = freePosting.get();}
                                    !{var i = freePosting.getIndex();}
                                    <option value="${p.getId()}">
                                        ${String.format("%d: %s - %s",i ,formatter.format(p.getDate()), p.getAmount())}
                                    </option>
                                @endfor
                            </select>
                        </td>
                        <td>
                            <button id="btnAddPosting" name="add_posting" type="submit">
                                ${localizer.localize("new_deposit.postings.add")}
                            </button>
                        </td>
                    </tr>
                    @endif
                    </tbody>
                </table>
            </div>
            @endif

            <footer>
                <div role="group">
                    <button role="button"
                            class="secondary reset_button"
                            type="reset"
                    >
                            ${localizer.localize("button.text.reset")}
                    </button>
                    <button role="button"
                            class="secondary cancel_button"
                            type="reset"
                    >
                            ${localizer.localize("button.text.cancel")}
                    </button>
                    <button autofocus type="submit"
                            role="button"
                            class="primary"
                    >
                            ${localizer.localize("button.text.submit")}
                    </button>
                </div>
            </footer>
        </form>
    </article>
</dialog>
