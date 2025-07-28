package rsh.domain.account.deposit;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import rsh.domain.account.deposit.interest.FlatInterestEntity;
import rsh.domain.account.deposit.interest.FlatPlusBonusAtEndInterestEntity;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DepositDto {//Long id,
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

    List<DepositRepository.PostingDto> freePostings;
    List<DepositRepository.PostingDto> assignedPostings;
    Long addPostingId;

    List<DepositRepository.TagDto> tags;

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
}
