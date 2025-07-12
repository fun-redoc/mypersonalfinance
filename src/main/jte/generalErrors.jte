@param rsh.web.ErrorsViewModel vwerrors
@if(vwerrors.hasNoFieldsMessages())
    <div class="error-message">
        <ul>
            @for(var error:vwerrors.getMessages())
                <li class="error">${error}</li>
            @endfor
        </ul>
    </div>
@endif
