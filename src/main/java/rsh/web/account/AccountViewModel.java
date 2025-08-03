package rsh.web.account;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import rsh.domain.account.AccountEntity;

import java.math.BigDecimal;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccountViewModel {
    private Long id;

    @NotNull(message = "accounts.add.field.error.accountType")
    private AccountEntity.AccountType accountType;

    @NotNull(message = "accounts.add.field.error.owner")
    private Long ownerEntityId;

    @NotBlank(message = "accounts.add.field.error.name")
    private String name;

    private String bank;

    // TODO check iban format and validate number using ... algorithm
    private String iban;

    @Min(value = 0, message = "accounts.field.error.balance")
    private BigDecimal balance;

    @NotNull(message = "accounts.add.field.error.date.created")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date dateCreated;

    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date dateClosed;

}

