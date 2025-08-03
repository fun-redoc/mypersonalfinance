package rsh.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.post.PostEntity;
import rsh.domain.account.post.PostRepository;

import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Controller
public class PostController extends ControllerBase  {
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PostDTO {
        @NotNull
        String name;
        @NotNull
        @DateTimeFormat(pattern = "yyyy-MM-dd")
        Date date;
        @NotNull
        Long fromAccountId;
        @NotNull
        Long toAccountId;
        @NotNull
        BigDecimal amount;
    }
    public enum DialogMode{CLOSED, ADD, EDIT}

    final PostRepository postRepository;
    final AccountRepository accountRepository;

    @Autowired
    public PostController(final PostRepository postRepository, final AccountRepository accountRepository) {
        this.postRepository = postRepository;
        this.accountRepository = accountRepository;
    }

    public record PostListDTO(Long id, Date date, String name, String fromAccountName, String toAccountName, BigDecimal amount){}
    @ModelAttribute("allPosts")
    public List<PostListDTO> allPosts() {
        return postRepository.findPostsByUserId(getUser().getId())
                .stream()
                .map( post ->
                        new PostListDTO(post.getId(),
                                post.getDate(),
                                post.getName(),
                                post.getFromAccountName(),
                                post.getToAccountName(),
                                post.getAmount()))
                .toList();
    }

    public record AccountListDTO(Long id, String name){}
    @ModelAttribute("allAccounts")
    public List<AccountListDTO> allAccounts() {
        return accountRepository
                .findBaseByUserId(getUser().getId())
                .stream()
                .map(a ->
                        new AccountListDTO(
                                a.getId(),
                                a.getName()))
                .toList();
    }

    @SuppressWarnings("SameReturnValue")
    @GetMapping("/posts")
    public String getPosts(@ModelAttribute("post") final PostDTO post,
                           @ModelAttribute("viewState") final PostViewState postViewState,
                           @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        post.setDate(Calendar.getInstance().getTime());
        postViewState.setDialogOpen(false);
        postViewState.setDialogMode(DialogMode.CLOSED);
        return "posts";
    }

    @PostMapping("/posts/add")
    public String addPost(@Valid @ModelAttribute("post") PostController.PostDTO post,
                          @ModelAttribute("state")  PostViewState postViewState,
                          BindingResult result) {
        if (result.hasErrors()) {
            postViewState.setDialogOpen(true);
            postViewState.setDialogMode(DialogMode.ADD);
            return "posts";
        }
        postViewState.setDialogOpen(false);
        postViewState.setDialogMode(DialogMode.CLOSED);
        postRepository.save(toEntity(null, post));
        return "redirect:/posts";

    }

    @GetMapping("/posts/edit/{id}")
    public String editPost(@PathVariable("id") final Long id,
                           @ModelAttribute("post") final PostDTO postDTO,
                           @ModelAttribute("state") final PostViewState postViewState) {
        var maybePostEntity = postRepository.findById(id);
        if(maybePostEntity.isPresent()) {
            var postEntity = maybePostEntity.get();
            fillPostDTOFromEntity(postDTO, postEntity);
            postViewState.setDialogOpen(true);
            postViewState.setDialogMode(DialogMode.EDIT);
            return "posts";
        } else {
            return "redirect:/posts?fail";
        }
    }

    @PostMapping("/posts/edit/{id}")
    public String editPost(@PathVariable("id") final Long id,
                           @Valid @ModelAttribute("post") final PostDTO postDTO,
                           @ModelAttribute("state") PostViewState state,
                           BindingResult bindingResult){
        if (bindingResult.hasErrors()) {
            state.setDialogOpen(true);
            state.setDialogMode(DialogMode.EDIT);
            return "posts";
        }
        state.setDialogOpen(false);
        state.setDialogMode(DialogMode.CLOSED);
        postRepository.save(toEntity(id, postDTO));
        return "redirect:/posts";
    }

    private PostEntity toEntity(Long id, PostDTO dto) {
        return accountRepository.findById(dto.getFromAccountId()).flatMap( fromId ->
                accountRepository.findById(dto.getToAccountId()).map(toId -> {
                    var e =  new PostEntity();
                    e.setId(id);
                    e.setDate(dto.getDate());
                    e.setAmount(dto.getAmount());
                    e.setFromAccount(fromId);
                    e.setToAccount(toId);
                    return e;
                })).orElseThrow();
    }

    public void fillPostDTOFromEntity(final PostDTO postDTO, final PostEntity entity) {
        postDTO.setDate(entity.getDate());
        postDTO.setFromAccountId(entity.getFromAccount().getId());
        postDTO.setToAccountId(entity.getToAccount().getId());
        postDTO.setAmount(entity.getAmount());
    }
}
