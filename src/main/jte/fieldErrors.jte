@param String fieldName
@param rsh.web.ErrorsViewModel vwerrors

@if(vwerrors.hasErrorForField(fieldName))
    <ul>
        @for(var error:vwerrors.getFieldMessages().get(fieldName))
            <li class="error">${error}</li>
        @endfor
    </ul>
@endif
