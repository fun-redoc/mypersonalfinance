package rsh.web.wealth;


import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import rsh.domain.account.wealth.WealthEntity;
import rsh.domain.account.wealth.WealthRepository;
import rsh.domain.account.wealth.purchase.PurchaseEntity;
import rsh.domain.account.wealth.purchase.PurchaseRepository;
import rsh.user.UserEntity;
import rsh.web.account.ControllerBase;
import rsh.web.base.ErrorsViewModel;

import java.math.BigDecimal;
import java.util.*;

@Controller
@RequestMapping("/wealth")
public class WealthController extends ControllerBase {
    @Data
    @Builder
    public static class PurchaseViewModel {
        Long id;
        Date purchaseDate;
        Long units;
        BigDecimal pricePerUnit;
        BigDecimal fee;
        String bank;
        // TODO one could assign a posting to a purchase
    }

    @Data
    @Builder
    public static class WealthViewModel {
       Long id;
       @NotNull
       String symbol;
       String name;
       String isin;
       @NotNull
       String wkn;
       List<PurchaseViewModel> purchases;
       PurchaseViewModel newPurchase;
    }

    final WealthRepository wealthRepository;
    final PurchaseRepository purchaseRepository;
    @Autowired
    public WealthController(final WealthRepository wealthRepository,
                            final PurchaseRepository purchaseRepository) {
        this.wealthRepository = wealthRepository;
        this.purchaseRepository = purchaseRepository;
    }

    @ModelAttribute("username")
    public String username() {
        return getUser().getUsername();
    }

    public record WealthListDto(Long id, String name){}
    public record WealthListViewModel(
        Long id, String symbol, String name,
        Long units, BigDecimal pricePerUnit, BigDecimal totalValue,
        Date inPortfolioSince){ }
    @ModelAttribute("allWealth")
    public List<WealthListViewModel> allWealth() {
        return
            wealthRepository.findWealthSummaryForUser(getUser().getId()).stream()
                    .map(dto -> new WealthListViewModel(dto.getId(),
                                                        dto.getSymbol(),
                                                        dto.getName(),
                                                        dto.getUnits(),
                                                        dto.getAvgUnitPrice(),
                                                        dto.getAvgUnitPrice() == null
                                                                ?null
                                                                :dto.getAvgUnitPrice().multiply(BigDecimal.valueOf(dto.getUnits())).add(dto.getSumFee()),
                                                        dto.getFirstTrade()))
                    .toList();
    }

    @GetMapping
    public String getWealth() {
        return "wealth";
    }
/*
    @GetMapping("/new")
    public String newWealth(@ModelAttribute final WealthViewModel wealthViewModel) {
        wealthViewModel.setPurchases(new ArrayList<>());
        wealthViewModel.setNewPurchase(PurchaseViewModel.builder().purchaseDate(Calendar.getInstance().getTime()).build());
        return "new_wealth";
    }

    //@PostMapping(value = {"/new"}, params = {"action"})
    @PostMapping(value = {"/new"})
    public String postNewWealth(@RequestParam(value = "action", required = false, defaultValue = "save") final String action,
                                @RequestParam(value = "id", required = false) final Long id,
                                @Valid @ModelAttribute final WealthViewModel wealthViewModel,
                                                BindingResult bindingResult){
        if(bindingResult.hasErrors()) {
            return "new_wealth";
        }

        switch(action) {
            case "add_purchase":
                final String bank = wealthViewModel.getNewPurchase().getBank();
                if(wealthViewModel.getPurchases() == null) {
                    wealthViewModel.setPurchases(new ArrayList<>());
                }
                wealthViewModel.getPurchases().add(wealthViewModel.getNewPurchase());
                wealthViewModel.setNewPurchase(PurchaseViewModel.builder().purchaseDate(Calendar.getInstance().getTime()).bank(bank).build());
                return "new_wealth";

            case "remove_purchase":
                if(id==null) {
                    System.err.println("id parameter cannot be null.");
                    return "new_wealth?fail";
                }
                wealthService.removePurchaseById(id);
                return "new_wealth";

            default:
                wealthService.save(
                        new WealthService.WealthDto(Optional.ofNullable(wealthViewModel.getId()),wealthViewModel.symbol, wealthViewModel.name, wealthViewModel.isin, wealthViewModel.wkn,
                                wealthViewModel.getPurchases().stream().map(p -> {
                                    return new WealthService.PurchaseDto(
                                        Optional.ofNullable(p.getId()),
                                        p.getPurchaseDate(),
                                        p.getUnits(),
                                        p.getPricePerUnit(),
                                        p.getBank(),
                                        p.getFee()
                                    );
                                }).toList())
                );
                return "redirect:/wealth";
        }

    }

 */

    @RequestMapping("/delete/{id}")
    @Transactional
    @Modifying
    public String deleteWealth(@PathVariable("id") Long id,
                               @ModelAttribute("vwerrors")ErrorsViewModel vwerrors) {
        var maybeWealth = wealthRepository.findByIdForUser(id, getUser().getId());
        return maybeWealth.map(wealthEntity -> {
            if(!isUserOwner(wealthEntity)) {
                System.err.println(String.format("wealth id %d does not belong to user %s, refused delete action.", id, getUser().getId()));
                vwerrors.getMessages().add("errors.message.generic");
                return "wealth";
            } else {
                wealthRepository.deleteById(id);
                return "redirect:/wealth";
            }
        }).orElseGet(() -> {
            System.err.println(String.format("wealth id %d does not exist for user id %s in DB.",id, getUser().getId()));
            vwerrors.getMessages().add("errors.message.generic");
            return "wealth";
        });
    }

    @GetMapping("/edit")
    public String newWealth(@ModelAttribute final WealthViewModel wealthViewModel) {
        wealthViewModel.setPurchases(new ArrayList<>());
        wealthViewModel.setNewPurchase(PurchaseViewModel.builder().purchaseDate(Calendar.getInstance().getTime()).build());
        return "wealth_new";
    }
    @PostMapping(value = {"/edit"})
    @Transactional
    @Modifying
    public String postNewWealth( @Valid @ModelAttribute final WealthViewModel wealthViewModel,
                                BindingResult bindingResult,
                                 @ModelAttribute("vwerrors") ErrorsViewModel vwerrors){
        var maybeWealthEntity = wealthRepository.findById(wealthViewModel.id);
        return maybeWealthEntity
            .map(wealthEntity -> {
                if(!isUserOwner(wealthEntity)) {
                    System.err.println(String.format("wealth entry with id %d dows not belong to user %s, edit action rejected.", wealthViewModel.id, getUser().getId()));
                    vwerrors.getMessages().add("errors.message.generic");
                    return "wealth_new";
                } else if(!wealthEntity.getId().equals(wealthViewModel.id)) {
                    System.err.println(String.format("wealth entry with id %d dows not match to id %d from DB, edit action rejected.", wealthViewModel.id, getUser().getId()));
                    vwerrors.getMessages().add("errors.message.generic");
                    return "wealth_new";
                } else if(bindingResult.hasErrors()) {
                        bindingResultToError(bindingResult, vwerrors);
                        return "wealth_new";
                } else {
                    var editPurchases = wealthViewModel.getPurchases();

                    if(!wealthEntity.getSymbol().equals(wealthViewModel.getSymbol())) {
                        wealthEntity.setSymbol(wealthViewModel.getSymbol());
                    }
                    if(!wealthEntity.getName().equals(wealthViewModel.getName())) {
                        wealthEntity.setName(wealthViewModel.getName());
                    }
                    if(!wealthEntity.getIsin().equals(wealthViewModel.getIsin())) {
                        wealthEntity.setIsin(wealthViewModel.getIsin());
                    }
                    if(wealthEntity.getWkn().equals(wealthViewModel.getWkn())) {
                        wealthEntity.setWkn(wealthViewModel.getWkn());
                    }

                    // there may b 3 kinds of purchases passed with the model from view
                    // 1. purchases alreday linked to wealthEntity
                    // 2. purchases yet not linked
                    // 3. purchases in wealthEntity no more present in view model, thus candidates to unlink

                    var currentlyAssignedPurchases = purchaseRepository.findAllByWealthEntity(wealthEntity);
                    var addedPurchases = wealthViewModel.getPurchases().stream()
                            .filter(viewPurchase ->
                                currentlyAssignedPurchases.stream()
                                        .map(PurchaseEntity::getId)
                                        .noneMatch(purchaseEntityId->purchaseEntityId.equals(viewPurchase.getId()))
                            );
                    var removedPurchases = currentlyAssignedPurchases.stream()
                            .filter(purchaseEntity ->
                                wealthViewModel.getPurchases().stream()
                                        .map(PurchaseViewModel::getId)
                                        .noneMatch(pid-> pid.equals(purchaseEntity.getId()))
                            );
                    removedPurchases.forEach(purchaseEntity -> {
                        purchaseRepository.delete(purchaseEntity);
                    });
                    var addedPurchaseEntities = addedPurchases.map(viewPurchase -> {
                       return PurchaseEntity.builder()
                               .id(viewPurchase.getId())
                               .bank(viewPurchase.getBank())
                               .belongsTo(wealthEntity.getBelongsTo())
                               .date(viewPurchase.getPurchaseDate())
                               .fee(viewPurchase.getFee())
                               .pricePerUnit(viewPurchase.getPricePerUnit())
                               .units(viewPurchase.getUnits())
                               .wealthEntity(wealthEntity)
                               .build();
                    }).toList();
                    purchaseRepository.saveAll(addedPurchaseEntities);
                    wealthRepository.save(wealthEntity);
                    return "redirect:/wealth";
                }
            }).orElseGet(() -> {
                System.err.println(String.format("wealth entry with id %d dows not exist in DB, edit action rejected.", wealthViewModel.id));
                vwerrors.getMessages().add("errors.message.generic");
                return "wealth_new";
            });
    }

    @GetMapping("/edit/{id}")
    public String edit(@PathVariable(value = "id", required = true) Long id,
                       @ModelAttribute WealthViewModel wealthViewModel,
                       @ModelAttribute("vwerrors") ErrorsViewModel vwerrors
    ) {
        var maybeWealthEntity = wealthRepository.findByIdForUser(id, getUser().getId());
            return maybeWealthEntity.map(wealthEntity -> {
                if(!isUserOwner(wealthEntity)) {
                    // this is superfluous
                    System.err.println(String.format("current user with id %s is not in owners of wealth entity with id %id, refusing to edit entity.",getUser().getId(), id));
                    vwerrors.getMessages().add("errors.message.generic");
                    return "wealth_new";
                } else {
                    wealthViewModel.setId(wealthEntity.getId());
                    wealthViewModel.setSymbol(wealthEntity.getSymbol());
                    wealthViewModel.setName(wealthEntity.getName());
                    wealthViewModel.setIsin(wealthEntity.getIsin());
                    wealthViewModel.setWkn(wealthEntity.getWkn());
                    var purchaseEntities = purchaseRepository.findAllByWealthEntity(wealthEntity);
                    wealthViewModel.setPurchases(
                            purchaseEntities.stream().map(purchase -> {
                                return PurchaseViewModel.builder()
                                        .id(purchase.getId())
                                        .purchaseDate(purchase.getDate())
                                        .pricePerUnit(purchase.getPricePerUnit())
                                        .units(purchase.getUnits())
                                        .bank(purchase.getBank())
                                        .fee(purchase.getFee())
                                        .build();
                            }).toList()
                    );
                    wealthViewModel.setNewPurchase(PurchaseViewModel.builder()
                                                    .purchaseDate(Calendar.getInstance().getTime())
                                                    .build());
                    return "new_wealth";
                }
                })
                .orElseGet(() -> {
                    System.err.println(String.format("wealth entity with id %id for user id %s does not exist in DB, refusing to edit entity.",id, getUser().getId()));
                    vwerrors.getMessages().add("errors.message.generic");
                    return "wealth_new";
                });
    }

    @RequestMapping(value="/edit/{id}", params={"add_purchase"})
    public String addPurchase(@PathVariable(value = "id", required = true) Long id,
                              @ModelAttribute WealthViewModel wealthViewModel,
                              BindingResult bindingResult,
                              @ModelAttribute("vwerrors") ErrorsViewModel vwerrors) {
        if(bindingResult.hasErrors()) {
            bindingResultToError(bindingResult, vwerrors);
            return "new_wealth";
        }
        if (id == null) {
            System.err.println("id parameter cannot be null. refusing to add wealth purchase.");
            vwerrors.getMessages().add("errors.message.generic");
            return "new_wealth";
        }
        return wealthRepository
                .findByIdForUser(id, getUser().getId())
                .map(wealthEntity -> {
                    final String bank = wealthViewModel.getNewPurchase().getBank();
                    if(wealthViewModel.getPurchases() == null) {
                        wealthViewModel.setPurchases(new ArrayList<>());
                    }
                    wealthViewModel.getPurchases().add(wealthViewModel.getNewPurchase());
                    wealthViewModel.setNewPurchase(PurchaseViewModel.builder().purchaseDate(Calendar.getInstance().getTime()).bank(bank).build());
                    return "new_wealth";
                }).orElseGet(() -> {
                    System.err.println(String.format("wealth id %d doesn't exist in DB for the user %s. refusing to add wealth purchase.", id, getUser().getId()));
                    vwerrors.getMessages().add("errors.message.generic");
                    return "new_wealth";
                });
    }

    @RequestMapping(value="/edit/{id}/{purchase_id}", params={"remove_purchase"})
    @Transactional
    @Modifying
    public String removePurchase(@PathVariable(value = "id", required = true) Long id,
                                 @PathVariable(value = "purchase_id", required = true) Long purchase_id,
                              @ModelAttribute WealthViewModel wealthViewModel,
                              BindingResult bindingResult,
                                 @ModelAttribute("vwerrors") ErrorsViewModel vwerrors) {

        if (bindingResult.hasErrors()) {
            bindingResultToError(bindingResult, vwerrors);
            return "new_wealth";
        }
        if (id == null) {
            System.err.println("id parameter cannot be null. refusing to delete wealth purchase.");
            vwerrors.getMessages().add("errors.message.generic");
            return "new_wealth";
        }
        if (purchase_id == null) {
            System.err.println("purchase id parameter cannot be null. refusing to delete purchase.");
            vwerrors.getMessages().add("errors.message.generic");
            return "new_wealth";
        }
        return purchaseRepository
            .findById(purchase_id)
            .map(purchaseEntity -> {
                purchaseRepository.deleteById(purchase_id);
                //return "new_wealth";
                return String.format("redirect:/wealth/edit/%d", wealthViewModel.getId());
            })
            .orElseGet(()->{
                System.err.println(String.format("user %s is not an owner of purchase id %d. refusing to delete.", getUser().getId(), purchase_id));
                vwerrors.getMessages().add("errors.message.generic");
                return "new_wealth";
            });
    }
    private boolean isUserOwner(WealthEntity wealthEntity) {
         return wealthEntity.getBelongsTo().getUsers().stream().map(UserEntity::getId).noneMatch(uid->uid.equals(getUser().getId()));
    }
}
