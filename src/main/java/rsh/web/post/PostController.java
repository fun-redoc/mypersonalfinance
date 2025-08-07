package rsh.web.post;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.deposit.DepositEntity;
import rsh.domain.account.deposit.DepositRepository;
import rsh.domain.account.post.PostEntity;
import rsh.domain.account.post.PostRepository;
import rsh.web.account.ControllerBase;
import rsh.web.base.ErrorsViewModel;

import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Controller
public class PostController extends ControllerBase {
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

        Long depositId;
    }
    public enum DialogMode{CLOSED, ADD, EDIT}

    final PostRepository postRepository;
    final DepositRepository depositRepository;
    final AccountRepository accountRepository;

    @Autowired
    public PostController(final PostRepository postRepository,
                          final AccountRepository accountRepository,
                            final DepositRepository depositRepository) {
        this.postRepository = postRepository;
        this.accountRepository = accountRepository;
        this.depositRepository = depositRepository;
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
                           @ModelAttribute("viewStatus") final PostViewState postViewState,
                           @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        post.setDate(Calendar.getInstance().getTime());
        postViewState.setDialogOpen(false);
        postViewState.setDialogMode(DialogMode.CLOSED);
        return "posts";
    }

    @PostMapping({"/posts/add", "/posts/new"})
    public String addPost(@Valid @ModelAttribute("post") PostController.PostDTO post,
                          BindingResult result,
                          @ModelAttribute("viewStatus") final PostViewState postViewState,
                          @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        if (result.hasErrors()) {
            postViewState.setDialogOpen(true);
            postViewState.setDialogMode(DialogMode.ADD);
            return "posts";
        }
        // check if the user is an owner for the from and to account
        var maybeFromAccount = accountRepository.findById(post.fromAccountId);
        if(maybeFromAccount.isEmpty()) {
            System.err.printf("from account with id %d not found for adding.%n", post.fromAccountId);
            postViewState.setDialogOpen(false);
            postViewState.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }
        var maybeToAccount = accountRepository.findById(post.toAccountId);
        if(maybeFromAccount.isEmpty()) {
            System.err.printf("to account with id %d not found for adding.%n", post.fromAccountId);
            postViewState.setDialogOpen(false);
            postViewState.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }
        // now the accounts exist, check the ownershaft
        if(!maybeToAccount.get()
                .getBelongsTo()
                .getUsers().stream()
                .anyMatch(u-> u.getId().equals(getUser().getId()))) {

            var msg = String.format("post cannot be added by user %s not beeing owner of to-account %d", getUser().getId(), maybeToAccount.get().getId());
            System.err.println(msg);
            postViewState.setDialogOpen(false);
            postViewState.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }
        if(!maybeFromAccount.get()
                .getBelongsTo()
                .getUsers().stream()
                .anyMatch(u-> u.getId().equals(getUser().getId()))) {

            var msg = String.format("post cannot be added by user %s not beeing owner of from-account %d", getUser().getId(), maybeFromAccount.get().getId());
            System.err.println(msg);
            postViewState.setDialogOpen(false);
            postViewState.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }

        // all checks passed, post can be saved
        postViewState.setDialogOpen(false);
        postViewState.setDialogMode(DialogMode.CLOSED);
        postRepository.save(toEntity(null, post));
        return "redirect:/posts";

    }

    @RequestMapping("/posts/delete/{deletePostId}")
    @Transactional
    @Modifying
    public String deletePost(@PathVariable("deletePostId") final Long deletePostId,
                           @ModelAttribute("viewStatus") final PostViewState postViewState,
                             @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        var maybeDeletePostEntity = postRepository.findById(deletePostId);
        try {
            return maybeDeletePostEntity
                    .map(deletePostEntity ->
                    {
                        if(deletePostEntity.getToAccount().getBelongsTo().getUsers().stream().anyMatch(u-> u.getId().equals(getUser().getId()))) {
                            // user belongs to the owners of the to account, thus is allowed to delete the posting
                            // TODO Documentation: document the fact that deletion of postings only for users in owner of to account
                            if(deletePostEntity.getDeposit() != null && deletePostEntity.getDeposit().getPosts() != null) {
                                deletePostEntity.getDeposit().getPosts().remove(deletePostEntity);
                            }
                            postRepository.deleteById(deletePostId);
                            return "redirect:/posts";
                        } else {
                            throw new AuthorizationDeniedException(String.format("post with id %d cannot be removed by user %s not beeing owner of to-account %d", deletePostId, getUser().getId(), deletePostEntity.getToAccount().getId()));
                        }
                    })
                    .orElseThrow();
        } catch (Exception e) {
            System.err.println(e);
            postViewState.setDialogOpen(false);
            postViewState.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.delete.failed");
            return "posts";
        }
    }

    @GetMapping("/posts/edit/{editPostId}")
    public String editPost(@PathVariable("editPostId") final Long id,
                           @ModelAttribute("post") final PostDTO postDTO,
                           @ModelAttribute("viewStatus") final PostViewState postViewState,
                            @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        var maybePostEntity = postRepository.findById(id);
        if(maybePostEntity.isPresent()) {
            var postEntity = maybePostEntity.get();
            try
            {
                if(postEntity.getToAccount().getBelongsTo().getUsers().stream().anyMatch(u-> u.getId().equals(getUser().getId()))) {
                    // user belongs to the owners of the to account, thus is allowed to delete the posting
                    // TODO Documentation: document the fact that editing of postings only for users in owner of to account
                    fillPostDTOFromEntity(postDTO, postEntity);
                    postViewState.setDialogOpen(true);
                    postViewState.setDialogMode(DialogMode.EDIT);
                    return "posts";
                } else {
                    throw new AuthorizationDeniedException(String.format("post with id %d cannot be edited by user %s not beeing owner of to-account %d", id, getUser().getId(), postEntity.getToAccount().getId()));
                }

            } catch (Exception e) {
                System.err.println(e);
                postViewState.setDialogOpen(false);
                postViewState.setDialogMode(DialogMode.CLOSED);
                vwerrors.getMessages().add("posts.error.delete.failed");
                return "posts";
            }
        } else {
            System.err.printf("post with id %d not found for editing.%n", id);
            postViewState.setDialogOpen(false);
            postViewState.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.edit.failed");
            return "posts";
        }
    }

    @PostMapping("/posts/edit/{id}")
    @Transactional
    @Modifying
    public String editPost(@PathVariable("id") final Long id,
                           @Valid @ModelAttribute("post") final PostDTO post,
                           BindingResult result,
                           @ModelAttribute("viewStatus") PostViewState viewStatus,
                            @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        if (result.hasErrors()) {
            viewStatus.setDialogOpen(true);
            viewStatus.setDialogMode(DialogMode.ADD);
            return "posts";
        }
        // check if the user is an owner for the from and to account
        var maybeFromAccount = accountRepository.findById(post.fromAccountId);
        if(maybeFromAccount.isEmpty()) {
            System.err.printf("from account with id %d not found for adding.%n", post.fromAccountId);
            viewStatus.setDialogOpen(false);
            viewStatus.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }
        var maybeToAccount = accountRepository.findById(post.toAccountId);
        if(maybeFromAccount.isEmpty()) {
            System.err.printf("to account with id %d not found for adding.%n", post.fromAccountId);
            viewStatus.setDialogOpen(false);
            viewStatus.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }
        // now the accounts exist, check the ownershaft
        if(!maybeToAccount.get()
                .getBelongsTo()
                .getUsers().stream()
                .anyMatch(u-> u.getId().equals(getUser().getId()))) {

            var msg = String.format("post cannot be added by user %s not beeing owner of to-account %d", getUser().getId(), maybeToAccount.get().getId());
            System.err.println(msg);
            viewStatus.setDialogOpen(false);
            viewStatus.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }
        if(!maybeFromAccount.get()
                .getBelongsTo()
                .getUsers().stream()
                .anyMatch(u-> u.getId().equals(getUser().getId()))) {

            var msg = String.format("post cannot be added by user %s not beeing owner of from-account %d", getUser().getId(), maybeFromAccount.get().getId());
            System.err.println(msg);
            viewStatus.setDialogOpen(false);
            viewStatus.setDialogMode(DialogMode.CLOSED);
            vwerrors.getMessages().add("posts.error.add.failed");
            return "posts";
        }
        viewStatus.setDialogOpen(false);
        viewStatus.setDialogMode(DialogMode.CLOSED);
        postRepository.save(toEntity(id, post));
        return "redirect:/posts";
    }

    private PostEntity toEntity(Long id, PostDTO dto) {
        return accountRepository.findById(dto.getFromAccountId()).flatMap( fromId ->
                accountRepository.findById(dto.getToAccountId()).map(toId -> {
                    var e =  new PostEntity();
                    e.setId(id);
                    e.setName(dto.getName());
                    e.setDate(dto.getDate());
                    e.setAmount(dto.getAmount());
                    e.setFromAccount(fromId);
                    e.setToAccount(toId);
                    //e.setDeposit(DepositEntity.builder().id(dto.getDepositId()).build());
                    if(dto.getDepositId() != null) {
                        depositRepository.findById(dto.getDepositId())
                                .ifPresent(depositEntity -> {
                                    e.setDeposit(depositEntity);
                                });
                    }
                    return e;
                })).orElseThrow();
    }

    public void fillPostDTOFromEntity(final PostDTO postDTO, final PostEntity entity) {
        postDTO.setName(entity.getName());
        postDTO.setDate(entity.getDate());
        postDTO.setFromAccountId(entity.getFromAccount().getId());
        postDTO.setToAccountId(entity.getToAccount().getId());
        postDTO.setAmount(entity.getAmount());
        if(entity.getDeposit() != null) {
            postDTO.setDepositId(entity.getDeposit().getId());
        } else {
            postDTO.setDepositId(null);
        }
    }
}
