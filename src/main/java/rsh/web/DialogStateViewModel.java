package rsh.web;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class DialogStateViewModel {
    public enum DialogMode{CLOSED, ADD,EDIT}
    private Boolean dialogOpen;
    private DialogMode dialogMode;
}
