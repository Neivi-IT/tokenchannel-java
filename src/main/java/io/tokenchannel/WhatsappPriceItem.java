package io.tokenchannel;

import lombok.Data;

import java.math.BigDecimal;

@Data
public class WhatsappPriceItem {
    private String code;
    private String country;
    private BigDecimal price;
}
