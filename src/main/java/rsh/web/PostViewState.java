package rsh.web;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PostViewState {
    Boolean dialogOpen;
    PostController.DialogMode dialogMode;
}
