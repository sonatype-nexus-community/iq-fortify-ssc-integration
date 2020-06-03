
package com.sonatype.ssc.integration.fortify.model.PolicyViolation;

import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "conditionSummary",
    "conditionReason"
})
public class Condition {

    @JsonProperty("conditionSummary")
    private String conditionSummary;
    @JsonProperty("conditionReason")
    private String conditionReason;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("conditionSummary")
    public String getConditionSummary() {
        return conditionSummary;
    }

    @JsonProperty("conditionSummary")
    public void setConditionSummary(String conditionSummary) {
        this.conditionSummary = conditionSummary;
    }

    @JsonProperty("conditionReason")
    public String getConditionReason() {
        return conditionReason;
    }

    @JsonProperty("conditionReason")
    public void setConditionReason(String conditionReason) {
        this.conditionReason = conditionReason;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

}
