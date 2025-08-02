package rsh.domain.account.deposit;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import rsh.domain.account.deposit.interest.FlatInterestEntity;
import rsh.domain.account.deposit.interest.FlatPlusBonusAtEndInterestEntity;
import rsh.web.ErrorsViewModel;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DepositDto {
    Long id;

    @NotNull(message = "depostis.error.name.missing")
    String name;

    @NotNull(message = "deposits.error.account.id.missing")
    Long accountId;

    String bank;

    @NotNull(message = "deposits.error.begin.data.missing")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    Date begin;

    @NotNull(message = "deposits.error.finish.date.missing")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    Date finish;
    //Long interestId;

    @NotNull(message = "deposits.error.")
    InterestEntity.InterestType interestType;

    //Interest zeroInterest;
    FlatInterestEntity flatInterest;
    FlatPlusBonusAtEndInterestEntity bonusInterest;

    BigDecimal effectiveInterest;

    List<DepositPostingDto> freePostings;
    List<DepositPostingDto> assignedPostings;
    Long addPostingId;

    List<DepositRepository.TagDto> tags;

    public void clear() {
        id = null;
        name = null;
        accountId = null;
        bank = null;
        begin = null;
        finish = null;
        interestType = null;
        flatInterest = null;
        bonusInterest = null;
        effectiveInterest = null;
        freePostings = new ArrayList<>();
        assignedPostings = new ArrayList<>();
        addPostingId = null;
        tags = new ArrayList<>();
    }

    public boolean isComplete() {
        return !name.isEmpty() &&
                (accountId != null) &&
                (begin != null) &&
                (finish != null) &&
                (switch (interestType) {
                    case FLAT -> flatInterest != null;
                    case ZERO -> true;
                    case FLAT_END_BONUS -> bonusInterest != null;
                    case null, default -> false;
                });
    }
    public boolean isComplete(final ErrorsViewModel vwerrors) {
        boolean res = true;
        if (name == null || name.isEmpty()) {
            vwerrors.getFieldMessages().put("name", List.of("deposits.name.required"));
            res = false;
        }
        if (accountId == null) {
            vwerrors.getFieldMessages().put("accountId", List.of("deposits.account.required"));
            res = false;
        }
        if (begin == null) {
            vwerrors.getFieldMessages().put("begin", List.of("deposits.begin.date.required"));
            res = false;
        }
        if (finish == null) {
            vwerrors.getFieldMessages().put("finish", List.of("deposits.finish.date.required"));
            res = false;
        }
        switch (interestType) {
            case FLAT: {
                if (flatInterest == null) {
                    vwerrors.getFieldMessages().put("flatInterestRate.flatInterest", List.of("deposits.flatInterestRate.required"));
                    res = false;
                }
            }
            break;
            case ZERO: {
            }
            break;
            case FLAT_END_BONUS: {
                if(bonusInterest == null) {
                    vwerrors.getFieldMessages().put("interestType", List.of("deposits.bonusInterest.required"));
                    res = false;
                } else {
                    if (bonusInterest.getAnnualRate() == null) {
                        vwerrors.getFieldMessages().put("bonusInterest.annualRate", List.of("deposits.annualRate.required"));
                        res = false;
                    }
                    if (bonusInterest.getFinalBonusRate() == null) {
                        vwerrors.getFieldMessages().put("bonusInterest.bonusInterest", List.of("deposits.bonusInterestRate.required"));
                        res = false;
                    }
                }
            }
            break;
            case null: {
                vwerrors.getFieldMessages().put("interestType", List.of("deposits.interestType.required"));
                res = false;
            }
            break;
        }
        return res;
    }
}
