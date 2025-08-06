@import org.springframework.security.web.csrf.CsrfToken
@import rsh.conf.JteLocalizer
@import rsh.web.auth.JteControllerAdvice
@import rsh.web.base.NullTollerantDateFormatter
@import rsh.web.post.PostController
@import rsh.web.post.PostViewState
@import java.text.SimpleDateFormat
@import java.util.Date
@import java.util.List
@param CsrfToken csrf
@param JteLocalizer localizer
@param NullTollerantDateFormatter formatter
@param PostViewState viewStatus
@param Long editPostId
@param List<PostController.PostListDTO> allPosts
@param List<PostController.AccountListDTO> allAccounts
@param PostController.PostDTO post
@param rsh.web.base.ErrorsViewModel vwerrors

@template.generalErrors(vwerrors = vwerrors)

    <section>
        <dialog id="modalEditAddDialog" open="${viewStatus.getDialogOpen()}">
            <article>
                <header>
                    <button
                            aria-label="Close"
                            rel="prev"
                            data-target="modalEditAddDialog"
                            onclick='toggleModal(event);window.location.replace("/posts");'
                    ></button>
                    <h2> ${viewStatus.getDialogMode().equals(PostController.DialogMode.EDIT)?
                             localizer.localize("posts.dialog.edit") : localizer.localize("posts.dialog.new")}
                    </h2>
                </header>
                !{var formAction = "#";}
                @if(viewStatus.getDialogMode().equals(PostController.DialogMode.EDIT))
                    !{formAction="/posts/edit/"+editPostId;}
                @elseif(viewStatus.getDialogMode().equals(PostController.DialogMode.ADD))
                    !{formAction="/posts/add";}
                @else
                        <%-- the dialog can be opened either via jte viewStatus setting
                                                      or via javascript modal.js called from a button etc.
                             in the second case, I asume add action in that case
                        --%>
                    !{formAction = "/posts/add";}
                @endif
                <form action="${formAction}" method="post">
                    @if(csrf != null)
                        <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
                    @endif
                    @if(post.getDepositId() != null)
                        <%-- pass through the deposit id if available --%>
                        <input type="hidden" name="depositId" value="${post.getDepositId()}">
                    @endif
                    <label for="name">${localizer.localize("posts.post.name")}</label>
                    <input type="text" id="name" name="name" value="${post.getName()}"
                            placeholder='${localizer.localize("posts.post.name")}'/>
                    @template.fieldErrors(fieldName="name", vwerrors = vwerrors, localizer = localizer)

                    <label for="date">${localizer.localize("posts.post.date")}</label>
                    <input type="date" id="date" name="date" value="${formatter.format(post.getDate())}"/>
                    @template.fieldErrors(fieldName="date", vwerrors = vwerrors, localizer = localizer)

                    <fieldset>
                        <legend>${localizer.localize("posts.post.from")}</legend>
                        <select name="fromAccountId" value="${post.getFromAccountId()}" aria-label="Select your from account." required>
                            <option selected disabled value="">${localizer.localize("posts.dialog.select.account")}</option>
                            @for(var ac:allAccounts)
                                @if(ac.id().equals(post.getFromAccountId()))
                                    <option selected value="${ac.id()}">${ac.name()}</option>
                                @else
                                    <option value="${ac.id()}">${ac.name()}</option>
                                @endif
                            @endfor
                        </select>
                    </fieldset>

                    <fieldset>
                        <legend>${localizer.localize("posts.post.to")}</legend>
                        <select name="toAccountId" value="${post.getToAccountId()}" aria-label="Select your to account." required>
                            <option selected disabled value="">${localizer.localize("posts.dialog.select.account")}</option>
                            @for(var ac:allAccounts)
                                @if(ac.id().equals(post.getToAccountId()))
                                    <option selected value="${ac.id()}">${ac.name()}</option>
                                @else
                                    <option value="${ac.id()}">${ac.name()}</option>
                                @endif
                            @endfor
                        </select>
                    </fieldset>

                    <label for="amount">${localizer.localize("posts.dialog.amount")}</label>
                    <input type="number" inputmode="decimal" min="0.01" step="0.01"  id="amount" name="amount" required value="${post.getAmount()}" />
                    @template.fieldErrors(fieldName="amount", vwerrors = vwerrors, localizer = localizer)

                    <%--
                        onclick='(event)->{toggleModal(event); /* window.location.replace("/posts");*/ }'>
                        --%>
                    <footer>
                        <div role="group">
                            <button role="button"
                                    class="secondary"
                                    data-target="modalEditAddDialog"
                                    onclick='toggleModal(event);window.location.replace("/posts");'>
                                    ${localizer.localize("button.text.cancel")}
                            </button>
                            <button autofocus type="submit"
                                    role="button"
                                    class="contrast"
                                   >${localizer.localize("button.text.submit")}
                            </button>
                        </div>
                    </footer>
                </form>
            </article>
        </dialog>
    </section>

<%--
  <section>
    <h2 th:text="#{posts.page}"></h2>

    <button id="btnOpenNewAccountModal"
            data-target="modalEditAddDialog"
            onclick="toggleModal(event)"
            th:text="#{posts.dialog.new}">
    </button>

    <div th:if="${param.fail}">
      <div class="error-message">
        <p th:text="#{errors.message.generic}">An error happened, try again later.</p>
      </div>
    </div>

    <dialog id="modalEditAddDialog" th:attr="open=${state.dialogOpen}">
      <article>
        <header>
          <button
                  aria-label="Close"
                  rel="prev"
                  data-target="modalEditAddDialog"
                  onclick="toggleModal(event)"
          ></button>
          <h2 th:text="${state.dialogMode.name()=='EDIT'}?#{posts.dialog.edit}:#{posts.dialog.new}"></h2>
        </header>
        <form th:action="${state.dialogMode.name()=='EDIT'}?@{/posts/edit/{id}(id=${id})}:@{/posts/add}" th:object="${post}" method="post">
          <label for="date" th:text="#{posts.post.date}">Date:</label>
          <input type="date" id="date" th:field="*{{date}}"/>
          <p th:if="${#fields.hasErrors('date')}" th:errors="*{date}"></p>

          <fieldset>
            <legend th:text="#{posts.post.from}">From Account</legend>
            <select th:field="*{fromAccountId}" aria-label="Select your from account." required>
              <option selected disabled value="" th:text="#{posts.dialog.select.account}">
                Select your from account..
              </option>
              <option th:each="ac:${allAccounts}" th:value="${ac.id}" th:text="${ac.name}">from Account Name</option>
            </select>
          </fieldset>

          <select th:field="*{toAccountId}" aria-label="Select your to account." required>
            <option selected disabled value="" th:text="#{posts.dialog.select.account}">
              Select your to account...
            </option>
            <option th:each="ac:${allAccounts}" th:value="${ac.id}" th:text="${ac.name}">to Account Name</option>
          </select>

          <label for="amount" th:text="#{posts.dialog.amount}">Amount</label>
          <input type="number" inputmode="decimal" min="0.01" step="0.01"  id="amount" name="amount" required th:field="*{amount}" />
          <p th:if="${#fields.hasErrors('amount')}" th:errors="*{amount}"></p>

          <footer>
            <div role="group">
              <button role="button"
                      class="secondary"
                      data-target="modalEditAddDialog"
                      onclick="toggleModal(event)"
                      th:text="#{button.text.cancel}">
                Cancel
              </button>
              <button autofocus type="submit"
                      role="button"
                      class="contrast"
                      th:text="#{button.text.submit}">
                Submit
              </button>
            </div>
          </footer>
        </form>
      </article>
    </dialog>
  </section>

  <!-- List of Accounts -->
  <section th:unless="${#lists.isEmpty(allPosts)}">
    <h2 th:text="#{posts.my_posts}">My Posts</h2>
    <table>
      <thead>
      <tr>
       <!-- <th th:text="#{posts.list.id}}>ID</th> -->
        <th th:text="#{posts.list.date}">Date</th>
        <th th:text="#{posts.list.amount}">Amount</th>
        <th th:text="#{posts.list.from}">from</th>
        <th th:text="#{posts.list.to}">to</th>
        <th th:text="#{posts.list.action}">Action</th>
      </tr>
      </thead>
      <tbody>
      <tr th:each="post : ${allPosts}">
<!--        <td th:text="${post.id}"></td> -->
        <td th:text="${post.date}"></td>
        <td th:text="${post.amount}"></td>
        <td th:text="${post.fromAccountName}"></td>
        <td th:text="${post.toAccountName}"></td>
        <td>
          <a th:href="@{/posts/edit/{id}(id=${post.id})}" role="button" th:text="#{button.text.edit}">Edit</a>
          <a th:href="@{/posts/delete/{id}(id=${post.id})}" role="button" class="secondary" th:text="#{button.text.delete}">Delete</a>
        </td>
      </tr>
      </tbody>
    </table>
  </section>
--%>