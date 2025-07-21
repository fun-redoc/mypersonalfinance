@import rsh.conf.JteLocalizer
@import rsh.user.UserBaseDto
@import rsh.web.SettingsController
@import java.util.ArrayList
@import java.util.HashMap
@import java.util.List
@import static org.springframework.data.jpa.domain.AbstractPersistable_.id
@param JteLocalizer localizer
@param List<UserBaseDto> users
@param SettingsController.OwnerWithUserIds editOwner
@param rsh.web.ErrorsViewModel vwerrors


<h2>${localizer.localize("settings.owner.assign.groups")}</h2>
<div class="assignment-area">
    <div class="assignment-list" id="availableUsers" ondragover="allowDrop(event)" ondrop="drop(event)">
        <h3>${localizer.localize("settings.owners.unassigned.users")}</h3>
        @for(var user:users)
            @if(editOwner.getUserIds().stream().noneMatch(uid-> uid.equals(user.getId())))
                <div class="assignment-list-item" draggable="true" ondragstart="drag(event)"
                     id="user${user.getId()}"
                     data-id="${user.getId()}"
                >${user.getUsername()}</div>
        @endif
        @endfor
    </div>

    <div class="assignment-list" id="assignedUsers" ondragover="allowDrop(event)" ondrop="drop(event)">
        <h3>${localizer.localize("settings.owner.assigned.users")}</h3>
        @for(var uid:editOwner.getUserIds())
            !{var user = users.stream().filter(u->u.getId().equals(uid)).findAny();}
            @if(user.isPresent())
                <div class="assignment-list-item" draggable="true" ondragstart="drag(event)"
                     id="user${uid}"
                     data-id="${uid}"
                >${user.get().getUsername()}</div>
            @endif
        @endfor
    </div>
</div>
