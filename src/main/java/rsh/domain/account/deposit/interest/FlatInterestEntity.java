package rsh.domain.account.deposit.interest;

import rsh.domain.base.ArithmeticsWithDates;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import rsh.domain.account.deposit.InterestEntity;

import java.math.BigDecimal;
import java.util.Date;

@EqualsAndHashCode(callSuper = true) // needed because of inheritance
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Entity
@DiscriminatorValue("flat")
public class FlatInterestEntity extends InterestEntity {
    private BigDecimal annualRate;
    private Date begin;
    private Date finish;
    public FlatInterestEntity(Date begin, Date finish, BigDecimal annualRate) {
        this.begin = begin;
        this.finish = finish;
        this.annualRate = annualRate;
    }
    @Override
    public BigDecimal calcRevenue(Date begin, Date end, BigDecimal amount) {
        Date startDateOfInterest = ArithmeticsWithDates.max(this.begin, begin);
        Date endDateOfIInterest = ArithmeticsWithDates.min(this.finish, end);
        var yearSplit = ArithmeticsWithDates.splitIntervalByYear(startDateOfInterest, endDateOfIInterest);
        return yearSplit.stream()
                .map(interval -> {
                    // map intervals to fractions of year
                    return BigDecimal.valueOf(ArithmeticsWithDates.calculateFractionOfYear(interval.begin(), interval.end()));
                })
                .reduce(amount, (total, yearFraction) -> {
                    // calculate the total
                    return total.add(annualRate.multiply(total).multiply(yearFraction));
                })
                .subtract(amount);
    }
    @Override
    public InterestType interestType() {
        return InterestType.FLAT;
    }

}
