package com.sonatype.ssc.integration.fortify.model;

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
        "sonatypeProject",
        "sonatypeProjectStage",
        "fortifyApplication",
        "fortifyApplicationVersion"
})
public class  MappingFile {

    @JsonProperty("sonatypeProject")
    private String sonatypeProject;
    @JsonProperty("sonatypeProjectStage")
    private String sonatypeProjectStage;
    @JsonProperty("fortifyApplication")
    private String fortifyApplication;
    @JsonProperty("fortifyApplicationVersion")
    private String fortifyApplicationVersion;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("sonatypeProject")
    public String getSonatypeProject() {
        return sonatypeProject;
    }

    @JsonProperty("sonatypeProject")
    public void setSonatypeProject(String sonatypeProject) {
        this.sonatypeProject = sonatypeProject;
    }

    @JsonProperty("sonatypeProjectStage")
    public String getSonatypeProjectStage() {
        return sonatypeProjectStage;
    }

    @JsonProperty("sonatypeProjectStage")
    public void setSonatypeProjectStage(String sonatypeProjectStage) {
        this.sonatypeProjectStage = sonatypeProjectStage;
    }

    @JsonProperty("fortifyApplication")
    public String getFortifyApplication() {
        return fortifyApplication;
    }

    @JsonProperty("fortifyApplication")
    public void setFortifyApplication(String fortifyApplication) {
        this.fortifyApplication = fortifyApplication;
    }

    @JsonProperty("fortifyApplicationVersion")
    public String getFortifyApplicationVersion() {
        return fortifyApplicationVersion;
    }

    @JsonProperty("fortifyApplicationVersion")
    public void setFortifyApplicationVersion(String fortifyApplicationVersion) {
        this.fortifyApplicationVersion = fortifyApplicationVersion;
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
