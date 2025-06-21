package rsh.domain.account.deposit.interest;

import org.springframework.data.jpa.repository.JpaRepository;
import rsh.domain.account.deposit.InterestEntity;

public interface InterestRepository extends JpaRepository<InterestEntity, Long> {
}
