package rsh.domain.account.deposit;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import rsh.domain.owner.OwnerEntity;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TagDto {
    @NotNull
    private Long id;

    @NotNull
    private String name;

}
