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
@param List<UserBaseDto> users
@param rsh.web.ErrorsViewModel vwerrors

<h2>${localizer.localize("settings.owner.assign.groups")}</h2>
<div class="assignment-area">
    <div class="assignment-list" id="available" ondragover="allowDrop(event)" ondrop="drop(event)">
        <h3>${localizer.localize("settings.owners.unassigned.users")}</h3>
        @for(var user:users)
            <div class="assignment-list-item" draggable="true" ondragstart="drag(event)" id="user${user.getId()}">${user.getUsername()}</div>
        @endfor
    </div>

    <div class="assignment-list" id="assigned" ondragover="allowDrop(event)" ondrop="drop(event)">
        <h3>${localizer.localize("settings.owner.assigned.users")}</h3>
    </div>
</div>

<%--
<script>
    function allowDrop(ev) {
      ev.preventDefault();
      ev.currentTarget.classList.add("over");
    }

    function drag(ev) {
      ev.dataTransfer.setData("text", ev.target.id);
    }

    function drop(ev) {
      ev.preventDefault();
      const data = ev.dataTransfer.getData("text");
      const dragged = document.getElementById(data);
      ev.currentTarget.appendChild(dragged);
      ev.currentTarget.classList.remove("over");
    }

    document.querySelectorAll(".box").forEach(box =>
      box.addEventListener("dragleave", () => box.classList.remove("over"))
    );
</script>
--%>