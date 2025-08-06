@param rsh.conf.JteLocalizer localizer = null
@param rsh.web.base.ErrorsViewModel vwerrors

@if(localizer == null)
    !{System.err.println("generalError.jte: localizer is null."); }
 @endif
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
