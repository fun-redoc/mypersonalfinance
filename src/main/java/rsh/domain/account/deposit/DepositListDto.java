package rsh.domain.account.deposit;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DepositListDto {
    private Long id;
    private String name;
    private Long accountId;
    private String bank;
    private Date begin;
    private Date end;
    private Long interestId;
    private BigDecimal amount;
    private BigDecimal effectiveInterest;
    private List<DepositRepository.TagDto> tags;
}
