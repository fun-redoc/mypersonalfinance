@import rsh.conf.JteLocalizer
@param String fieldName
@param rsh.web.ErrorsViewModel vwerrors
@param JteLocalizer localizer

!{var defaultMessage = localizer.localize("errors.field.message.generic");}

@if(vwerrors.hasErrorForField(fieldName))
    <ul>
        @for(var error:vwerrors.getFieldMessages().get(fieldName))
            !{var message = localizer.get(error).orElse(defaultMessage);}
            <li class="error">${message}</li>
        @endfor
    </ul>
@endif
