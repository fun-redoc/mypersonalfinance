package rsh.domain.account.wealth;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import rsh.domain.owner.OwnerEntity;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "wealth")
public class WealthEntity {
    @Id
    @SequenceGenerator(name = "wealth_seq", sequenceName = "wealth_seq", initialValue = 1, allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "wealth_seq")
    @Column(name = "id", updatable = false, nullable = false, unique = true)
    private Long id;

    @PrimaryKeyJoinColumn
    @ManyToOne
    private OwnerEntity belongsTo;

    @NotNull
    private String symbol;

    private String name;
    private String isin;
    private String wkn;

}
