package rsh.domain.account.post;

import jakarta.persistence.Column;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.Nullable;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.deposit.DepositEntity;

import java.math.BigDecimal;
import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PostDto {
    private Long id;

    @NotNull(message = "posts.error.name.mandatory")
    private String name;

    @NotNull(message = "posts.error.date.mandatory")
    private Date date;

    @NotNull(message = "posts.error.fromAccount.mandatory")
    private Long fromAccountId;

    private String fromAccountName;

    @NotNull(message = "posts.error.toAccount.mandatory")
    private Long toAccountId;

    private String toAccountName;

    @NotNull(message = "posts.error.amount.mandatory")
    private BigDecimal amount;

    private Long depositId; // some post will belong to deposits (but not all)
}
