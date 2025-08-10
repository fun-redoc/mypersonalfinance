package rsh.web.deposit;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.deposit.*;
import rsh.domain.account.deposit.interest.FlatInterestEntity;
import rsh.domain.account.deposit.interest.FlatPlusBonusAtEndInterestEntity;
import rsh.domain.account.deposit.interest.InterestRepository;
import rsh.domain.account.post.PostEntity;
import rsh.domain.account.post.PostRepository;
import rsh.user.UserEntity;
import rsh.web.base.ErrorsViewModel;
import rsh.web.account.ControllerBase;
import rsh.web.base.Pair;

import java.math.BigDecimal;
import java.util.*;
        import java.util.stream.Collectors;
import java.util.stream.Stream;

@Controller
public class DepositController extends ControllerBase {

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DepositPageStatus {
        public enum DialogMode{EDIT, NEW, CLOSED}

        boolean showOnlyCurrent;
        boolean onlyCheck;
        boolean hideActions;
        boolean dialogOpen;
        DialogMode dialogMode;
    }

    @Autowired
    TransactionTemplate transactionTemplate;

    final DepositRepository depositRepository;
    final PostRepository postRepository;
    final AccountRepository accountRepository;
    private final InterestRepository interestRepository;
    private final TagRepository tagRepository;
    //final DepositPageStatus state = new DepositPageStatus(false, true);

    @Autowired
    public DepositController(final DepositRepository depositRepository,
                             final PostRepository postRepository,
                             final AccountRepository accountRepository,
                             InterestRepository interestRepository,
                             TagRepository tagRepository) {
        this.depositRepository = depositRepository;
        this.postRepository = postRepository;
        this.accountRepository = accountRepository;
        this.interestRepository = interestRepository;
        this.tagRepository = tagRepository;
    }

    @ModelAttribute("allDeposits")
    public List<DepositListDto> allDeposits() {
        var user = getUser();
        var ds =  depositRepository
                .findDepositsForUser(UserEntity.builder().id(user.getId()).build());
        var ds1 = ds.stream().map(d -> {
                    d.setTags(depositRepository.getTagsByDepositId(d.getId()));
                    d.setEffectiveInterest(
                            interestRepository.findById(d.getInterestId())
                                    .map(i-> i.effectiveInterestPa())
                                    .orElse(null)
                    );
                    return d;
                }).toList();
        return ds1;
    }

    @ModelAttribute("allInterestTypes")
    public List<InterestEntity.InterestType> allInterestTypes() {
        return Arrays.asList(InterestEntity.InterestType.values());
    }

    @ModelAttribute("allAccounts")
    public List<DepositRepository.AccountListDTO> allAccounts() {
        var user = getUser();
        return accountRepository
                .findBaseByUserId(user.getId())
                .stream()
                .map(a ->new DepositRepository.AccountListDTO(a.getId(), a.getName(), a.getBank()))
                .toList();
    }

    //public record TagListDTO(Long id, String name){}
    //@ModelAttribute("allTags")
    //    public List<TagListDTO> allTags() {
    //    return depositService
    //            .findAllTags()
    //            .stream()
    //            .map(a ->new TagListDTO(a.getId(), a.getName()))
    //            .toList();
    //}

    @ModelAttribute("today")
    public Date today() {
        return Calendar.getInstance().getTime();
    }

    //@ModelAttribute("state")
    //public DepositPageStatus getState() {
    //    return this.state;
    //}

    @GetMapping(value = "/deposits")
    public String getDeposits(
            @ModelAttribute("deposit") DepositDto depositDto,
            @ModelAttribute("viewStatus") DepositPageStatus viewStatus,
            @ModelAttribute("vwerrors") ErrorsViewModel vwerrors) {
        viewStatus.setHideActions(false);
        viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
        viewStatus.setDialogOpen(false);
        return "deposits";
    }

    @GetMapping(value = "/deposits", params = {"showOnlyCurrent"})
//    public String getDeposits(final String showOnlyCurrent) {
    public String getDeposits(@ModelAttribute("viewStatus")  final DepositPageStatus viewStatus) {
//        this.state.setShowOnlyCurrent(showOnlyCurrent.equals("yes"));
        viewStatus.setHideActions(false);
        viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
        viewStatus.setDialogOpen(false);
        return "deposits";
    }

    @GetMapping(value = "/deposits/new")
    public String getNewDeposit(@ModelAttribute("deposit")    final DepositDto depositDto,
                                @ModelAttribute("viewStatus") final DepositPageStatus viewStatus,
                                @ModelAttribute("vwerrors")   final ErrorsViewModel vwerrors
    ) {
        var cal = Calendar.getInstance();
        depositDto.clear();
        depositDto.setBegin(cal.getTime());
        cal.add(Calendar.YEAR, 1);
        depositDto.setFinish(cal.getTime());
        viewStatus.setDialogMode(DepositPageStatus.DialogMode.NEW);
        viewStatus.setDialogOpen(true);
        return "deposits";
    }

    @GetMapping("/deposits/edit/{id}")
    public String getEditDeposit(@PathVariable("id") final Long editId,
                                 @ModelAttribute("deposit") final DepositDto depositDto,
                                 @ModelAttribute("viewStatus") final DepositPageStatus viewStatus,
                                 @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        if(editId == null) {
            System.err.println("/deposits/edit called with id set to null");
            vwerrors.getMessages().add("errors.message.generic");
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
            viewStatus.setDialogOpen(false);
            return "deposits";
        }

        return depositRepository.findById(editId)
        .flatMap(depositEntity -> {
            if(depositEntity
                    .getBelongsTo().getUsers().stream()
                    .map(UserEntity::getId)
                    .noneMatch(uid -> uid.equals(getUser().getId()))) {
                System.err.println("/deposits/edit called with id set to null");
                vwerrors.getMessages().add("errors.message.generic");
                viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
                viewStatus.setDialogOpen(false);
                return Optional.empty();
            } else {
                return Optional.of(depositEntity);
            }
        })
        .map( depositEntity -> {
            depositDto.setId(depositEntity.getId());
            depositDto.setName(depositEntity.getName());
            depositDto.setTags(depositEntity.getTags().stream().map(t-> new DepositRepository.TagDto(t.getId(), t.getName())).toList());
            depositDto.setAccountId(depositEntity.getAccount().getId());
            depositDto.setAssignedPostings(depositEntity.getPosts().stream()
                                            .map(p->DepositPostingDto.builder()
                                                                .id(p.getId())
                                                                .date(p.getDate())
                                                                .amount(p.getAmount())
                                                            .build()).toList());
            depositDto.setFreePostings(new ArrayList<>(getFreePostingsFromDb(depositEntity.getAccount().getId())));
            depositDto.setBank(depositEntity.getAccount().getBank());
            depositDto.setBegin(depositEntity.getBegin());
            depositDto.setFinish(depositEntity.getDue());
            depositDto.setInterestType(depositEntity.getInterest().interestType());
            switch (depositDto.getInterestType()) {
                case ZERO: {
                    depositDto.setEffectiveInterest(BigDecimal.ZERO);
                };break;
                case FLAT: {
                    depositDto.setFlatInterest((FlatInterestEntity) depositEntity.getInterest());
                    depositDto.setEffectiveInterest(depositEntity.getInterest().effectiveInterestPa());
                };break;
                case FLAT_END_BONUS: {
                    depositDto.setBonusInterest((FlatPlusBonusAtEndInterestEntity) depositEntity.getInterest());
                    depositDto.setEffectiveInterest(depositEntity.getInterest().effectiveInterestPa());
                };break;
                default:{
                    throw new RuntimeException("Unexpected Interest Type");
                }
            }
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.EDIT);
            viewStatus.setDialogOpen(true);
            return "deposits";
        }).orElseGet(()->{
            System.err.println(String.format("no entity found for id %d", editId));
            vwerrors.getMessages().add("errors.message.generic");
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
            viewStatus.setDialogOpen(false);
            return "deposits";
        });
    }

    @RequestMapping(value = {"/deposits/add", "/deposits/new", "/deposits/edit/{editId}"}, params = {"action"})
    public String actionHandler( @RequestParam (name = "action", required = true) final String action,
                                 @RequestParam (name = "id", required = false) final Long id,
                                 @PathVariable(value = "editId",required = false) final Long editId,
                                 @ModelAttribute("viewStatus") DepositPageStatus depositPageStatus,
                                 @ModelAttribute("vwerrors")   final ErrorsViewModel vwerrors,
                                 @Valid @ModelAttribute("deposit") final DepositDto depositDto,
                                 final BindingResult bindingResultDeposit
                                 //@ModelAttribute("deposit") final DepositDto depositDto
                                 //,final Model model
    ) {
        if(depositDto.getAccountId() != null) {
            //
        }
        var dialogMode = DepositPageStatus.DialogMode.NEW;
        if(editId != null) {
            dialogMode = DepositPageStatus.DialogMode.EDIT;
            depositDto.setId(editId);
        }
        switch(action) {
            case "account":
                depositDto.setFreePostings(new ArrayList<>(getFreePostingsFromDb(depositDto.getAccountId())));
                depositDto.setAssignedPostings(new ArrayList<>());
                depositPageStatus.setDialogMode(dialogMode);
                depositPageStatus.setDialogOpen(true);
                break;
            case "interest_type":
                var interestType = depositDto.getInterestType();
                if(interestType != null ) {
                    switch (depositDto.getInterestType()) {
                        //case ZERO: depositDto.setZeroInterest(new Interest());break;
                        case ZERO: break;
                        case FLAT: depositDto.setFlatInterest(new FlatInterestEntity());break;
                        case FLAT_END_BONUS: depositDto.setBonusInterest(new FlatPlusBonusAtEndInterestEntity());break;
                        default:throw new RuntimeException("unexpected.");
                    }
                }
                adjustAssignedAndFreePostings(depositDto);
                depositPageStatus.setDialogMode(dialogMode);
                depositPageStatus.setDialogOpen(true);
                break;
            case "add_posting":
                adjustAssignedAndFreePostings(depositDto);
                depositPageStatus.setDialogMode(dialogMode);
                depositPageStatus.setDialogOpen(true);
                break;
            case "remove_posting":
                if(id == null) {
                    throw new IllegalArgumentException("id of the posting to remove expected but got null.");
                }
                if(depositDto.getAssignedPostings() == null) {
                    throw new IllegalArgumentException("no postings to remove available.");
                }

                DepositPostingDto postingToDelete = null;
                for(var assignedPosting : depositDto.getAssignedPostings()) {
                    if(assignedPosting.getId() == id) {
                        postingToDelete = assignedPosting;
                        break;
                    }
                }
                if(postingToDelete == null) {
                    throw new IllegalArgumentException(String.format("posting {} is not available to remove.", id));
                }

                if(!depositDto.getAssignedPostings().remove(postingToDelete)) {
                    throw new IllegalArgumentException(String.format("failed removing posting {} ", id));
                }


                var filterIds = depositDto.getAssignedPostings().stream()
                        .map(p->p.getId()).toList();

                var filteredFreePostings= filterFreePostings(depositDto.getAccountId(),
                        filterIds);
                depositDto.setFreePostings(filteredFreePostings);
                depositDto.getFreePostings().add(postingToDelete);

                depositPageStatus.setDialogMode(dialogMode);
                depositPageStatus.setDialogOpen(true);
                break;
            default:throw new RuntimeException("unknown action");
        }
        return "deposits";
    }

    private void adjustAssignedAndFreePostings(DepositDto depositDto) {
        if(depositDto.getAssignedPostings() == null) {
            depositDto.setAssignedPostings(new ArrayList<>());
        }

        if(depositDto.getFreePostings() == null) {
            depositDto.setFreePostings(new ArrayList<>());
        } else {
            depositDto.getFreePostings().clear();
        }
        var freePostings = getFreePostingsFromDb(depositDto.getAccountId());

        var assignedPostings = depositDto.getAssignedPostings();
        for(var p:freePostings) {
            if(!Objects.equals(p.getId(), depositDto.getAddPostingId()) && !assignedPostings.contains(p)) {
                depositDto.getFreePostings().add(p);
            } else {
                if(Objects.equals(p.getId(), depositDto.getAddPostingId())) {
                    depositDto.getAssignedPostings().add(p);
                }
            }
        }
    }

    @PostMapping({"/deposits/add", "/deposits/new"})
    @Transactional
    @Modifying
    public String addDeposit(
                             @ModelAttribute("viewStatus") final DepositPageStatus viewStatus,
                             @ModelAttribute("vwerrors")   final ErrorsViewModel vwerrors,
                             @Valid @ModelAttribute("deposit") final DepositDto depositDto,
                             final BindingResult bindingResultDeposit,
                             final Model model) {
        if(bindingResultDeposit.hasErrors()) {
            bindingResultToError(bindingResultDeposit, vwerrors);
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.NEW);
            viewStatus.setDialogOpen(true);
            return "deposits";
        }
        if(!depositDto.isComplete(vwerrors)) {
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.NEW);
            viewStatus.setDialogOpen(true);
            return "deposits";
        }
        var maybeDepositEntity =  accountRepository
                .findById(depositDto.getAccountId())
                .map(a->{ var depositEntity = DepositEntity.builder().build();
                    depositEntity.setAccount(a);
                    depositEntity.setBelongsTo(a.getBelongsTo()); // TODO check if there is a need for deposits and account to belong to different groups/owners
                    depositEntity.setInterest(switch (depositDto.getInterestType()) {
                        case ZERO -> new InterestEntity();
                        case FLAT -> new FlatInterestEntity(depositDto.getBegin(), depositDto.getFinish(), depositDto.getFlatInterest().getAnnualRate());
                        case FLAT_END_BONUS -> new FlatPlusBonusAtEndInterestEntity(depositDto.getBegin(), depositDto.getFinish(), depositDto.getBonusInterest().getAnnualRate(), depositDto.getBonusInterest().getFinalBonusRate());
                        default -> throw new RuntimeException("unexpected.");
                    });
                    depositEntity.setName(depositDto.getName());
                    depositEntity.setBegin(depositDto.getBegin());
                    depositEntity.setDue(depositDto.getFinish());
                    depositEntity.setPosts(depositDto.getAssignedPostings().stream().map(dto -> {
                                var p = postRepository.findById(dto.getId());
                                p.ifPresent(p_->p_.setDeposit(depositEntity));
                                return p.orElseThrow();
                            })
                            .collect(Collectors.toUnmodifiableList()));
                    //depositEntity.setTags(depositDto.getTags().stream().map(t -> {
                    //    return TagEntity.builder()
                    //            .name(t.getName())
                    //            .id(t.getId())
                    //            .build();
                    //}).collect(Collectors.toSet()));
                    return depositEntity;
                });

        if(maybeDepositEntity.isPresent()) {
            var depositEntity = depositRepository.save(maybeDepositEntity.get());
            if(depositEntity == null) {
                System.err.printf("Saving of deposit failed for user id %s, repository save returned with null value%n", getUser().getId() );
                vwerrors.getMessages().add("deposits.save.failed");
                viewStatus.setDialogMode(DepositPageStatus.DialogMode.NEW);
                viewStatus.setDialogOpen(true);
                return "deposits";
            } else {
                // add Tags here because i need depositEntity to be managed
                // first collect tags already available
                if(depositDto.getTags() != null && !depositDto.getTags().isEmpty()) {
                    var ownersTags = tagRepository.findAllByBelongsTo(depositEntity.getBelongsTo());

                    var addedOwnersTags = ownersTags.stream().filter(t ->
                            depositDto.getTags().stream()
                                    .map(DepositRepository.TagDto::getName)
                                    .anyMatch(tagName -> tagName.equals(t.getName()))
                    )
                    .map(tagEntity -> {
                        depositEntity.addTag(tagEntity);
                        return tagEntity;
                    }).toList();
                    var persistedAddedOwnerTags = tagRepository.saveAll(addedOwnersTags);
                    // second add new tags
                    var newTags = depositDto.getTags().stream().filter(tagDto ->
                            ownersTags.stream()
                                    .map(TagEntity::getName)
                                    .noneMatch(tagDto.getName()::equals)
                    ).map(tagDto ->
                            TagEntity.builder()
                                    .belongsTo(depositEntity.getBelongsTo())
                                    .name(tagDto.getName())
                                    .id(tagDto.getId())
                                    .deposits(new HashSet<>())
                                    .build()
                    )
                    .map(tagEntity -> {
                        depositEntity.addTag(tagEntity);
                        return tagEntity;
                    }).toList();
                    var persistedNewTagEntity = tagRepository.saveAll(newTags);
                }
                return "redirect:/deposits";
            }
        } else {
            System.err.printf("Saving of deposit failed for user id %s, deposit entity object is empty%n", getUser().getId() );
            vwerrors.getMessages().add("deposits.save.failed");
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.NEW);
            viewStatus.setDialogOpen(true);
            return "deposits";
        }

    }

    @RequestMapping(value = "/deposits/delete/{id}")
    @Transactional
    @Modifying
    public String removeDeposit(@PathVariable("id") final Long id,
                             @ModelAttribute("viewStatus") final DepositPageStatus viewStatus,
                             @ModelAttribute("vwerrors")   final ErrorsViewModel vwerrors
    ) {
        if(id==null) {
            System.err.printf("Deleting of deposit failed for user id %s, parameter id has null value%n", getUser().getId() );
            vwerrors.getMessages().add("deposits.delete.failed");
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
            viewStatus.setDialogOpen(false);
            return "deposits";
        }
        // delete deposits and all assignments, eg. in deposits_tags table, deposit_posts etc.
        var maybeDepositEntity = depositRepository.findById(id);
        if(maybeDepositEntity.isEmpty()) {
            System.err.printf("Deleting of deposit failed for user id %s, no deposit for id %d available%n", getUser().getId(), id );
            vwerrors.getMessages().add("deposits.delete.failed");
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
            viewStatus.setDialogOpen(false);
            return "deposits";
        }
        return maybeDepositEntity.map(depositEntity -> {
            depositRepository.delete(depositEntity);
            depositEntity.getTags().forEach(tagEntity -> {tagEntity.getDeposits().remove(depositEntity);});
            depositEntity.getPosts().forEach(postEntity -> {postEntity.setDeposit(null);});
            return "redirect:/deposits";
        }).orElse("deposits");
    }

    @PostMapping("/deposits/edit/{editId}")
//    @Transactional I manually control the Trx here
    @Modifying
    public String postEditDeposit(@PathVariable("editId") final Long editId,
                                  @Valid @ModelAttribute("deposit") final DepositDto depositDto,
                                  BindingResult result,
                                  @ModelAttribute("viewStatus") final DepositPageStatus viewStatus,
                                  @ModelAttribute("vwerrors") final ErrorsViewModel vwerrors) {
        if(editId == null) {
            System.err.println("editId cannot be null.");
            viewStatus.setDialogOpen(true);
            viewStatus.setDialogMode(DepositPageStatus.DialogMode.EDIT);
            vwerrors.getMessages().add("errors.message.generic");
            return "deposits";
       }
        // TODO check all input data from depositDto first, don't trust Entity Annotations
       return transactionTemplate.execute(status -> {
           try {
               var maybeDepositEntity = depositDtoToEntity(editId, depositDto);
               return maybeDepositEntity
                .map(depositEntity -> {
                       viewStatus.setDialogOpen(false);
                       viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
                       //status.flush();
                       return "redirect:/deposits";
                   }).orElseGet(()-> {
                       System.err.println(String.format("editId %d is no entity.",editId));
                       viewStatus.setDialogOpen(true);
                       viewStatus.setDialogMode(DepositPageStatus.DialogMode.EDIT);
                       vwerrors.getMessages().add("errors.message.generic");
                       return "deposits";
                   });
           } catch (Exception e) {
               // TODO Rollback
               System.err.println(String.format("Error happened while persisting edited deposit %d is no entity. Rollback issued. Cause:\n %s",editId, e));
               viewStatus.setDialogOpen(false);
               viewStatus.setDialogMode(DepositPageStatus.DialogMode.CLOSED);
               vwerrors.getMessages().add("errors.message.generic");
               status.setRollbackOnly();
               return "deposits";
           }
       });
    }

    private List<DepositPostingDto> getFreePostingsFromDb(Long accountId) {
        return postRepository
                .findPostsByToAccountAndDepositIsNull(getUser().getId(), accountId)
                .stream().map(entity ->
                        new DepositPostingDto(entity.getId(),
                                entity.getDate(),
                                entity.getAmount()))
                .toList();
    }
    private List<DepositPostingDto> filterFreePostings(Long accountId, List<Long> filterPostingsIds) {

        var freePostings = getFreePostingsFromDb(accountId);
        var res = new ArrayList<DepositPostingDto>();

        for(var free:freePostings) {
            boolean isFiltered = false;
            for(var filterId:filterPostingsIds) {
                if(free.getId().equals(filterId)) {
                    isFiltered = true;
                    break;
                }
            }
            if(!isFiltered) {
                res.add(free);
            }
        }
        return res;
    }

    private Optional<DepositEntity> depositDtoToEntity(final Long depositId, final DepositDto depositDto) {
        if(depositDto == null || depositId == null && depositDto.getId() == null) {
            System.err.println("cannot determin id for DepositEntity.");
            return Optional.empty();
        }
        var entityId = depositId == null ? depositDto.getId() : depositId;
        try {
            return depositRepository.findById(entityId)
                    .flatMap(depositEntity -> {
                        // check if user is one of the owners
                        if (depositEntity.getBelongsTo()
                                .getUsers().stream()
                                .map(UserEntity::getId)
                                .noneMatch(uid -> uid.equals(getUser().getId()))) {
                            System.err.println(String.format("editId %d doesn't belong to user %s is no entity.", depositId, getUser().getId()));
                            return Optional.empty();
                        } else {
                            return Optional.of(depositEntity);
                        }
                    })
                    .flatMap(depositEntity -> {
                        // check if the account in the user entry matches the entity
                        // return updated deposit and a flag indicating the account change
                        if (!depositEntity.getAccount().getId().equals(depositDto.getAccountId())) {
                            // maybe account has changed
                            return accountRepository.findById(depositDto.getAccountId())
                                    .flatMap(accountEntity -> {
                                        if (!accountEntity.getBelongsTo().getUsers().stream().map(UserEntity::getId).toList().contains(getUser().getId())) {
                                            System.err.println(String.format("given account %d for deposit %d does not belong to user %s", accountEntity.getId(), depositId, getUser().getId()));
                                            return Optional.empty();
                                        } else {
                                            depositEntity.setAccount(accountEntity);
                                            return Optional.of(new Pair<DepositEntity, Boolean>(depositEntity, true));
                                        }
                                    }).or(() -> {
                                        System.err.println(String.format("given acoount id %d for deposit %d does not exist in database", depositDto.getAccountId(), depositId));
                                        return Optional.empty();
                                    });
                        } else {
                            return Optional.of(new Pair<>(depositEntity, false));
                        }
                    })
                    .flatMap(depositEntityWithAcccountChangeFlag -> {
                        var depositEntity = depositEntityWithAcccountChangeFlag.first();
                        var accountChangeFlag = depositEntityWithAcccountChangeFlag.second();
                        // adjust interest and other flat properties
                        var interest = switch (depositDto.getInterestType()) {
                            case ZERO -> new InterestEntity();
                            case FLAT ->
                                    new FlatInterestEntity(depositDto.getBegin(), depositDto.getFinish(), depositDto.getFlatInterest().getAnnualRate());
                            case FLAT_END_BONUS ->
                                    new FlatPlusBonusAtEndInterestEntity(depositDto.getBegin(), depositDto.getFinish(), depositDto.getBonusInterest().getAnnualRate(), depositDto.getBonusInterest().getFinalBonusRate());
                            default -> throw new RuntimeException("unexpected.");
                        };
                        if (!depositEntity.getInterest().sameAs(interest)) {
                            depositEntity.setInterest(interest);
                        }
                        if (!depositEntity.getName().equals(depositDto.getName())) {
                            depositEntity.setName(depositDto.getName());
                        }
                        if (!depositEntity.getBegin().equals(depositDto.getBegin())) {
                            depositEntity.setBegin(depositDto.getBegin());
                        }
                        if (!depositEntity.getDue().equals(depositDto.getFinish())) {
                            depositEntity.setDue(depositDto.getFinish());
                        }
                        if(accountChangeFlag) {
                            // account changed, unlink all postings
                            depositEntity.getPosts().forEach(postEntity -> {
                               postEntity.setDeposit(null);
                            });
                            depositEntity.getPosts().clear();
                        }
                        var allOldPosts = depositEntity.getPosts();
                        Stream<PostEntity> deletedPosts = null;
                        if(depositDto.getAssignedPostings() != null && depositDto.getAssignedPostings().size() > 0) {
                            deletedPosts = allOldPosts.stream().filter(postEntity -> {
                                return depositDto.getAssignedPostings().stream()
                                        .map(DepositPostingDto::getId)
                                        .noneMatch(pid -> postEntity.getId().compareTo(pid) == 0);
                            });
                        }
                        if(depositDto.getAssignedPostings() != null && depositDto.getAssignedPostings().size() > 0) {
                            var addedPostIds = depositDto.getAssignedPostings().stream()
                                    .map(DepositPostingDto::getId)
                                    .filter(pid -> allOldPosts.stream().noneMatch(p -> p.getId().compareTo(pid) == 0))
                                    .toList();
                        }
                        if(deletedPosts != null) {
                            deletedPosts.forEach(p -> {
                                depositEntity.removePost(p);
                            });
                        }
                        if(depositDto.getAssignedPostings() != null && depositDto.getAssignedPostings().size() > 0) {
                            postRepository.findAllById(
                                        depositDto.getAssignedPostings().stream()
                                                .map(dto -> {
                                                    return dto.getId();
                                                }).collect(Collectors.toUnmodifiableList())
                                ).forEach(p -> {
                                    depositEntity.addPost(p);
                                });
                        }

                        // adjust tags, reuse tags already persisted for this owner
                        // first collect tags already available
                        if (depositDto.getTags() != null) {
                            var assignedTags = depositEntity.getTags();
                            var assignedTagNames = assignedTags.stream()
                                    .map(tagEntity -> tagEntity.getName()).collect(Collectors.toSet());
                            var editedTagNames = depositDto.getTags().stream().map(dto -> dto.getName()).toList();
                            // tags for this deposit are possibly edited
                            var superFluousTags = assignedTags.stream()
                                    .filter(tagEntity -> !editedTagNames.contains(tagEntity.getName()))
                                    .toList();
                            // second add new tags
                            var unassignedTagNames = editedTagNames.stream()
                                    .filter(name -> !assignedTagNames.contains(name))
                                    .toList();
                            var unassignedPersistedTags = tagRepository.findAllByBelongsToAndNames(depositEntity.getBelongsTo(), unassignedTagNames);
                            var unassignedNotPersistedTags = unassignedTagNames.stream()
                                    .filter(name -> unassignedPersistedTags.stream()
                                            .map(tagEntity -> tagEntity.getName())
                                            .noneMatch(persistedName -> persistedName.equals(name)))
                                    .map(name -> {
                                        return TagEntity.builder()
                                                .name(name)
                                                .belongsTo(depositEntity.getBelongsTo())
                                                .deposits(new HashSet<>())
                                                .build();
                                    })
                                    .toList();
                            superFluousTags.forEach(tagEntity -> {
                                depositEntity.removeTag(tagEntity);
                            });
                            var persistedDepositEntity = depositRepository.save(depositEntity);
                            unassignedPersistedTags.forEach(tagEntity -> {
                                persistedDepositEntity.addTag(tagEntity);
                            });
                            unassignedNotPersistedTags.forEach(tagEntity -> {
                                persistedDepositEntity.addTag(tagEntity);
                            });
                            var newlyPersistedTags = tagRepository.saveAll(unassignedNotPersistedTags);
                            return Optional.of(depositRepository.save(depositEntity));
                        } else {
                            // no tags, maybe all are discarded
                            if(depositEntity.getTags() != null && depositEntity.getTags().size() > 0){
                                depositEntity.getTags().forEach(tagEntity -> {
                                   tagEntity.getDeposits().remove(depositEntity);
                                });
                                depositEntity.getTags().clear();
                            }
                            return Optional.of(depositRepository.save(depositEntity));
                        }
                    }).or(() -> {
                        System.err.println(String.format("DepositEntity not found for id: %d", entityId));
                        return Optional.empty();
                    });
        } catch (Exception e) {
            System.err.printf("%s\n", e);
            e.printStackTrace(System.err);
            throw new RuntimeException(e);
        }
    }
}
