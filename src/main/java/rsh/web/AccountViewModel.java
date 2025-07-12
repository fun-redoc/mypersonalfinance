package rsh.web;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import rsh.domain.account.AccountEntity;
import rsh.domain.owner.OwnerEntity;

import java.math.BigDecimal;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccountViewModel {
    private Long id;

    @NotNull
    private AccountEntity.AccountType accountType;

    @NotNull
    private Long ownerEntityId;

    @NotBlank(message = "Account name is mandatory")
    private String name;

    private String bank;

    // TODO check iban format and validate number using ... algorithm
    private String iban;

    @Min(value = 0, message = "Balance must be a positive number")
    private BigDecimal balance;

    @NotNull
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date dateCreated;

    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date dateClosed;
}

