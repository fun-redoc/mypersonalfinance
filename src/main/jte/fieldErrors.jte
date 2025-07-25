@import rsh.conf.JteLocalizer
@param String fieldName
@param rsh.web.ErrorsViewModel vwerrors
@param JteLocalizer localizer

    <ul id="err-${fieldName}">
        @if(vwerrors.hasErrorForField(fieldName))
            @for(var error:vwerrors.getFieldMessages().get(fieldName))
                !{var message = localizer.get(error).orElse(localizer.localize("errors.field.message.generic"));}
                <li class="error">${message}</li>
            @endfor
        @endif
    </ul>
