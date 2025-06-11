@import org.springframework.security.web.csrf.CsrfToken
@param CsrfToken csrf

<%-- include this within every form --%>
@if(csrf != null)
    <input type="hidden" name="${csrf.getParameterName()}" value="${csrf.getToken()}">
@endif