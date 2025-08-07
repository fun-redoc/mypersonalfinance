package rsh.domain.account.deposit.interest;

import rsh.domain.account.deposit.InterestEntity;
import rsh.domain.base.ArithmeticsWithDates;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.math.BigDecimal;
import java.util.Date;

@EqualsAndHashCode(callSuper = true) // needed because of inheritance
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Entity
@DiscriminatorValue("flat_end_bonus")
public class FlatPlusBonusAtEndInterestEntity extends InterestEntity {
    private BigDecimal annualRate;
    private Date begin;
    private Date finish;
    private BigDecimal finalBonusRate;
    public FlatPlusBonusAtEndInterestEntity(Date begin, Date finish, BigDecimal annualRate, BigDecimal finalBonusRate) {
        this.begin = begin;
        this.finish = finish;
        this.annualRate = annualRate;
        this.finalBonusRate = finalBonusRate;
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
                .multiply(BigDecimal.ONE.add(finalBonusRate))
                .subtract(amount);
    }
    @Override
    public InterestType interestType() {
        return InterestType.FLAT_END_BONUS;
    }

    @Override
    public boolean sameAs(InterestEntity other) {
        // compares every parameter but id
        if(other.getClass() != FlatPlusBonusAtEndInterestEntity.class) {
            return false;
        }
        var castOther = (FlatPlusBonusAtEndInterestEntity) other;
        return interestType() == other.interestType() &&
                begin.equals(castOther.begin) &&
                finish.equals(castOther.finish) &&
                annualRate.compareTo(castOther.annualRate) == 0 &&
                finalBonusRate.compareTo(castOther.finalBonusRate) == 0;


    }
}
