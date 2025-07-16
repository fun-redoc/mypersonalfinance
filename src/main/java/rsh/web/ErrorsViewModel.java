package rsh.web;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ErrorsViewModel {
    public ErrorsViewModel(List<String> _messages, Map<String,List<String>> _fieldMessages) {
        if(_messages==null) {
            this.messages = new ArrayList<>();
        } else {
            this.messages = _messages;
        }
        if(_fieldMessages == null) {
            this.fieldMessages = new HashMap<>();
        } else {
            this.fieldMessages = _fieldMessages;
        }
    }
    public ErrorsViewModel() {
        messages = new ArrayList<>();
        fieldMessages = new HashMap<>();
    }
   List<String> messages; // general error messages without reference to a field
   Map<String, List<String>> fieldMessages; // key is the name of the input field
    public boolean hasNoFieldsMessages() {
        return messages.size() > 0;
    }
    public boolean hasErrorForField(String fieldName) {
        return fieldName != null
                && fieldMessages.size() > 0
                && fieldMessages.containsKey(fieldName)
                && fieldMessages.get(fieldName).size() > 0;
    }

}
