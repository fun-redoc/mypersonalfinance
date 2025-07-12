package rsh.user;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.cache.annotation.Cacheable;
import rsh.domain.owner.OwnerEntity;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Cacheable
public class UserBaseDto {
    private String id;
    private String username;
    private String email;
}