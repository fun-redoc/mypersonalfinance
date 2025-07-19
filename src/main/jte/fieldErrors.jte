@import rsh.conf.JteLocalizer
@param String fieldName
@param rsh.web.ErrorsViewModel vwerrors
@param JteLocalizer localizer

!{var defaultMessage = localizer.localize("errors.field.message.generic");}

    <ul id="err-${fieldName}">
        @if(vwerrors.hasErrorForField(fieldName))
            @for(var error:vwerrors.getFieldMessages().get(fieldName))
                !{var message = localizer.get(error).orElse(defaultMessage);}
                <li class="error">${message}</li>
            @endfor
        @endif
    </ul>
