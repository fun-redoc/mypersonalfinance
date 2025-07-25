package rsh.domain.account;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.Date;

//public interface AccountsBaseData {
//    Long getId();
//    rsh.domain.account.AccountEntity.AccountType getAccountType();
//    String getName();
//    String getIban();
//    String getBank();
//    Date getDateCreated();
//    Date getDateClosed();
//    Long getOwnerId();
//    String getOwnerName();
//    BigDecimal getKred();
//    BigDecimal getDeb();
//}
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AccountsBaseData {
    Long id;
    AccountEntity.AccountType accountType;
    String name;
    String iban;
    String bank;
    Date dateCreated;
    Date dateClosed;
    Long ownerId;
    String ownerName;
    BigDecimal kred; // TODO carve out calculated values out of here
    BigDecimal deb;
}
