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
@param PostViewState viewStatus
@param rsh.web.base.ErrorsViewModel vwerrors
@param List<PostController.PostListDTO> allPosts
@param PostController.PostDTO post
@param List<PostController.AccountListDTO> allAccounts
@param Long editPostId
@param String username
@param Date today

!{NullTollerantDateFormatter formatter = new NullTollerantDateFormatter(new SimpleDateFormat("yyyy-MM-dd"));}

!{var pageContent = @`

    @template.generalErrors(vwerrors = vwerrors)

    @template.posts_new(csrf = csrf, localizer = localizer, formatter = formatter, viewStatus = viewStatus, editPostId = editPostId, allPosts = allPosts, allAccounts = allAccounts, post = post, vwerrors = vwerrors)

    <!--symotion-f) List of Accounts -->
    <section>
        <div role="group">
            <h2>${localizer.localize("posts.my_posts")}</h2>

            <button id="btnOpenNewAccountModal"
                    data-target="modalEditAddDialog"
                    onclick="toggleModal(event)"
            >${localizer.localize("posts.dialog.new")}
            </button>
        </div>
        @if(!allPosts.isEmpty())
        <table>
            <thead>
            <tr>
                <!-- <th th:text="#{posts.list.id}}>ID</th> -->
                <th>${localizer.localize("posts.list.date")}</th>
                <th>${localizer.localize("posts.list.amount")}</th>
                <th>${localizer.localize("posts.list.from")}</th>
                <th>${localizer.localize("posts.list.to")}</th>
                <th>${localizer.localize("posts.list.action")}</th>
            </tr>
            </thead>
            <tbody>
            @for(var post:allPosts)
            <tr>
                <!--        <td th:text="${post.id()}"></td> -->
                <td>${formatter.format(post.date())}</td>
                <td>${post.amount()}</td>
                <td>${post.fromAccountName()}</td>
                <td>${post.toAccountName()}</td>
                <td>
                    <a href="/posts/edit/${post.id()}" role="link">${localizer.localize("button.text.edit")}</a>
                    <a href="/posts/delete/${post.id()}" role="link" class="secondary">${localizer.localize("button.text.delete")}</a>
                </td>
            </tr>
            @endfor
            </tbody>
        </table>
        @endif
    </section>
`;}

@template.layout(
localizer =localizer,
currentMenu = JteControllerAdvice.MenuItem.POSTS,
page = localizer.localize("posts.page"),
content = pageContent,
additional_head = @`
    <script src="/security.js" ></script>
`
)

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