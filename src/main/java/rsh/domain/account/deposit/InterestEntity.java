package rsh.domain.account.deposit;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.math.BigDecimal;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE) // expecting few instances, otherwise switch to other strategies
@DiscriminatorColumn(name = "interest_type")
public class InterestEntity {
    public enum InterestType{ZERO,FLAT,FLAT_END_BONUS} // TODO may be some future version of JPA will support enums as discrimiinator values
    // subcalss this for special interest conditions
    // override calcRevenue
    @Id
    @GeneratedValue
    private Long id;

    // TODO the follwing methods have to be overriden
    public BigDecimal calcRevenue(Date begin, Date end, BigDecimal amount) {
        // Default Implementation no Interest
        return BigDecimal.ZERO;
    }
    public BigDecimal effectiveInterestPa() {
        // Default Implementation no Interest
        return BigDecimal.ZERO;
    }

    public InterestType interestType() {
        return InterestType.ZERO;
    }
}
