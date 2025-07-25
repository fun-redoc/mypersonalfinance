@param rsh.conf.JteLocalizer localizer = null
@param rsh.web.ErrorsViewModel vwerrors

@if(vwerrors.hasNoFieldsMessages())
    <div class="error-message">
        <ul>
            @if(localizer == null)
                @for(var error:vwerrors.getMessages())
                    <li class="error">${error}</li>
                @endfor
            @else
                @for(var error:vwerrors.getMessages())
                    !{var message = localizer.get(error).orElse(localizer.localize("errors.field.message.generic"));}
                    <li class="error">${message}</li>
                @endfor
            @endif
        </ul>
    </div>
@endif
