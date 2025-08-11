package rsh.domain.account.wealth;

import lombok.Data;

import java.math.BigDecimal;
import java.util.Date;

@Data
public class WealthSummaryDto {
    Long id;
    String symbol;
    String name;
    Long units;
    BigDecimal avgUnitPrice;
    Long cntPricePerUnit;
    BigDecimal sumFee;
    Date firstTrade;
    Date lastTrade;

    public WealthSummaryDto(Long id, String symbol, String name, Long units, BigDecimal fee, Double pricePerUnit, Long cnt, Date firstTrade, Date lastTrade) {
        this.id = id;
        this.symbol = symbol;
        this.name = name;
        this.units = units;
        if(pricePerUnit != null) {
            this.avgUnitPrice = BigDecimal.valueOf(pricePerUnit) ;
        }
        this.cntPricePerUnit = cnt;
        this.sumFee = fee;
        this.firstTrade = firstTrade;
        this.lastTrade = lastTrade;
    }
}
