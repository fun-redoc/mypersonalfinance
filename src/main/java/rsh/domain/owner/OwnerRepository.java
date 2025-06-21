package rsh.domain.owner;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OwnerRepository extends JpaRepository<OwnerEntity, String> {
    Optional<OwnerEntity> findOwnerByName(String name);
}
