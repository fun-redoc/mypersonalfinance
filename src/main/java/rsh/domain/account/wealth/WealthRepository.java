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
}
