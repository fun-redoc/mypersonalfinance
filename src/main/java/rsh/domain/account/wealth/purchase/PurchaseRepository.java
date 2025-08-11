package rsh.domain.account.wealth.purchase;

import org.springframework.data.jpa.repository.JpaRepository;
import rsh.domain.account.wealth.WealthEntity;

import java.util.List;

public interface PurchaseRepository extends JpaRepository<PurchaseEntity, Long> {
    List<PurchaseEntity> findAllByWealthEntity(WealthEntity wealthEntity);
}
