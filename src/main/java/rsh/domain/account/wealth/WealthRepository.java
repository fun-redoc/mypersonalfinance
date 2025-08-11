package rsh.domain.account.wealth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.account.wealth.purchase.PurchaseEntity;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

public interface WealthRepository extends JpaRepository<WealthEntity, Long> {
    @Query("""
            select w
            from WealthEntity w
            left join w.belongsTo o
            where 
                :uid in elements(o.users)
            and :id = w.id
            """)
    Optional<WealthEntity> findByIdForUser(@Param("id") Long id, @Param("uid") String uid);

    @Query("""
            select p from PurchaseEntity p
            where p.wealthEntity = :w
            """)
    List<PurchaseEntity> allPurchasesForWealth(@Param("w") WealthEntity wealthEntity);


    @Query("""
            select sum(units)*avg(pricePerUnit) + sum(fee)
            from PurchaseEntity
            where wealthEntity = :w
            """)
    Optional<BigDecimal> wealthCostOfPurchase(@Param("w") WealthEntity wealthEntity);
    
    @Query("""
            select new  com.rsh.wealth.domain.wealth.WealthSummaryDto(
                w.id,
                w.symbol,
                w.name,
                sum(p.units),
                sum(p.fee),
                avg(p.pricePerUnit),
                count(p.pricePerUnit),
                min(date),
                max(date))
            from WealthEntity as w
                left join w.belongsTo o
                left join PurchaseEntity as p on p.wealthEntity.id = w.id
            where :userId in elements(o.users)
            group by w.id
            """)
    List<WealthSummaryDto> findWealthSummaryForUser(String userId);
}
