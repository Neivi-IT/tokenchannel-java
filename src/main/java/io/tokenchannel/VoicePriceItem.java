package io.tokenchannel;

import lombok.Data;

import java.math.BigDecimal;

@Data
public class VoicePriceItem {
    private String code;
    private String country;
    private String type;
    private BigDecimal price;
}
