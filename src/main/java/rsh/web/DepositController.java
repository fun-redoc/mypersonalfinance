package rsh.web;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.deposit.*;
import rsh.domain.account.deposit.interest.FlatInterestEntity;
import rsh.domain.account.deposit.interest.FlatPlusBonusAtEndInterestEntity;
import rsh.domain.account.deposit.interest.InterestRepository;
import rsh.domain.account.post.PostDto;
import rsh.domain.account.post.PostRepository;
import rsh.user.UserEntity;

import java.math.BigDecimal;
import java.util.*;
        import java.util.stream.Collectors;

@Controller
public class DepositController extends ControllerBase {

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DepositPageStatus {
        boolean showOnlyCurrent;
        boolean onlyCheck;
        boolean hideActions;
    }

    final DepositRepository depositRepository;
    final PostRepository postRepository;
    final AccountRepository accountRepository;
    private final InterestRepository interestRepository;
    //final DepositPageStatus state = new DepositPageStatus(false, true);

    @Autowired
    public DepositController(final DepositRepository depositRepository,
                             final PostRepository postRepository,
                             final AccountRepository accountRepository,
                             InterestRepository interestRepository) {
        this.depositRepository = depositRepository;
        this.postRepository = postRepository;
        this.accountRepository = accountRepository;
        this.interestRepository = interestRepository;
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
            @ModelAttribute("viewStatus") DepositPageStatus viewStatus,
            @ModelAttribute("vwerrors") ErrorsViewModel vwerrors) {
        viewStatus.setHideActions(false);
        return "deposits";
    }
    @GetMapping(value = "/deposits", params = {"showOnlyCurrent"})
//    public String getDeposits(final String showOnlyCurrent) {
    public String getDeposits(@ModelAttribute  final DepositPageStatus depositPageStatus) {
//        this.state.setShowOnlyCurrent(showOnlyCurrent.equals("yes"));

        return "deposits";
    }

    @GetMapping(value = "/deposits/new")
    public String getNewDeposit(@ModelAttribute("deposit") final DepositDto depositDto
                                //,Model model
    ) {
        var cal = Calendar.getInstance();
        depositDto.setName("");
        depositDto.setBegin(cal.getTime());
        cal.add(Calendar.YEAR, 1);
        depositDto.setFinish(cal.getTime());
        //depositDto.setZeroInterest(new Interest());
        depositDto.setTags(new ArrayList<>());
        //depositDto.setTags(depositService
        //        .findAllTags()
        //        .stream()
        //        .map(a ->new TagDto(a.getId(), a.getName()))
        //        .toList());
        return "new_deposit";
    }

    @RequestMapping(value = {"/deposits/add", "/deposits/new"}, params = {"action"})
    public String actionHandler( @RequestParam (name = "action", required = true) final String action,
                                 @RequestParam (name = "id", required = false) final Long id,
                                 @Valid @ModelAttribute("deposit") final DepositDto depositDto,
                                 final BindingResult bindingResultDeposit
                                 //,final Model model
    ) {
        if(depositDto.getAccountId() != null) {
            var freePostings = getFreePostingsFromDb(depositDto.getAccountId());
            depositDto.setFreePostings(new ArrayList<>(freePostings));
        }
        switch(action) {
            case "account":
                depositDto.setAssignedPostings(new ArrayList<>());
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
                break;
            case "add_posting":
                if(depositDto.getAssignedPostings() == null) {
                    depositDto.setAssignedPostings(new ArrayList<>());
                }

                depositDto.setFreePostings(new ArrayList<>());
                var freePostings = getFreePostingsFromDb(depositDto.getAccountId());

                var assignedPostings = depositDto.getAssignedPostings();
                for(var p:freePostings) {
                    if(!Objects.equals(p.id(), depositDto.getAddPostingId()) && !assignedPostings.contains(p)) {
                        depositDto.getFreePostings().add(p);
                    } else {
                        if(Objects.equals(p.id(), depositDto.getAddPostingId())) {
                            depositDto.getAssignedPostings().add(p);
                        }
                    }
                }
                break;
            case "remove_posting":
                if(id == null) {
                    throw new IllegalArgumentException("id of the posting to remove expected but got null.");
                }
                if(depositDto.getAssignedPostings() == null) {
                    throw new IllegalArgumentException("no postings to remove available.");
                }

                DepositRepository.PostingDto postingToDelete = null;
                for(var assignedPosting : depositDto.getAssignedPostings()) {
                    if(assignedPosting.id() == id) {
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
                        .map(p->p.id()).toList();

                var filteredFreePostings= filterFreePostings(depositDto.getAccountId(),
                        filterIds);
                depositDto.setFreePostings(filteredFreePostings);

                break;
            default:throw new RuntimeException("unknown action");
        }
        return "new_deposit";
    }

    @PostMapping({"/deposits/add", "/deposits/new"})
    public String addDeposit(@Valid @ModelAttribute("deposit") DepositDto depositDto,
                             BindingResult bindingResultDeposit,
                             Model model) {
        if(bindingResultDeposit.hasErrors()) {
            //return "new_deposit?fail";
            return "new_deposit";
        }
        if(!depositDto.isComplete()) {
            return "new_deposit";
        }
        var maybeDepositEntity =  accountRepository
                .findById(depositDto.getAccountId())
                .map(a->{ var depositEntity = DepositEntity.builder().build();
                    depositEntity.setAccount(a);
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
                                var p = postRepository.findById(dto.id());
                                p.ifPresent(p_->p_.setDeposit(depositEntity));
                                return p.orElseThrow();
                            })
                            .collect(Collectors.toSet()));

                    depositEntity.setTags(depositDto.getTags().stream().map(t -> {
                        return TagEntity.builder()
                                .name(t.getName())
                                .id(t.getId())
                                .build();
                    }).collect(Collectors.toSet()));
                    return depositEntity;
                });

        if(maybeDepositEntity.isPresent()) {
            depositRepository.save(maybeDepositEntity.get());
            return "redirect:/deposits";
        } else {
            System.err.println("something went wrong");
            return "new_deposit?fail"; // TODO LOG Error
        }

    }

    @RequestMapping(value = "/deposits/delete/{id}")
    public String removeDeposit(@PathVariable("id") final Long id) {
        if(id==null) {
            return "redirect:/deposits?fail";
        }
        // delete deposits and all assignments, eg. in deposits_tags table
        depositRepository.deleteById(id);
        return "redirect:/deposits";
    }

    private List<DepositRepository.PostingDto> getFreePostingsFromDb(Long accountId) {
        return postRepository
                .findPostsByToAccountAndDepositIsNull(getUser().getId(), accountId)
                .stream().map(entity ->
                        new DepositRepository.PostingDto(entity.getId(),
                                entity.getDate(),
                                entity.getAmount()))
                .toList();
    }
    private List<DepositRepository.PostingDto> filterFreePostings(Long accountId, List<Long> filterPostingsIds) {

        var freePostings = getFreePostingsFromDb(accountId);
        var res = new ArrayList<DepositRepository.PostingDto>();

        for(var free:freePostings) {
            boolean isFiltered = false;
            for(var filterId:filterPostingsIds) {
                if(free.id().equals(filterId)) {
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
}
