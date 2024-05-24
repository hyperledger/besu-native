package org.hyperledger.besu.nativelib.ipa_multipoint.proof;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;


public class ExecutionWitnessData {

    @JsonProperty("header")
    public Header header;
    @JsonProperty("transactions")
    public List<String> transactions;
    @JsonProperty("withdrawals")
    public List<String> withdrawals;
    @JsonProperty("executionWitness")
    public ExecutionWitness executionWitness;


    static class Header {

        @JsonProperty("blockNumber")
        public String blockNumber;
        @JsonProperty("parentHash")
        public String parentHash;
        @JsonProperty("coinbase")
        public String coinbase;
        @JsonProperty("stateRoot")
        public String stateRoot;
        @JsonProperty("receiptsRoot")
        public String receiptsRoot;
        @JsonProperty("logsBloom")
        public String logsBloom;
        @JsonProperty("gasLimit")
        public String gasLimit;
        @JsonProperty("gasUsed")
        public String gasUsed;
        @JsonProperty("timestamp")
        public String timestamp;
        @JsonProperty("extraData")
        public String extraData;
        @JsonProperty("baseFeePerGas")
        public String baseFeePerGas;
        @JsonProperty("blockHash")
        public String blockHash;
        @JsonProperty("prevRandao")
        public String prevRandao;
        @JsonProperty("transactionsTrie")
        public String transactionsTrie;

    }


    static class ExecutionWitness {

        @JsonProperty("stateDiff")
        public List<StateDiff> stateDiff;
        @JsonProperty("verkleProof")
        public VerkleProof verkleProof;

    }


    static class StateDiff {

        @JsonProperty("stem")
        public String stem;
        @JsonProperty("suffixDiffs")
        public List<SuffixDiff> suffixDiffs;

    }


    static class SuffixDiff {

        @JsonProperty("suffix")
        public int suffix;
        @JsonProperty("currentValue")
        public String currentValue;
        @JsonProperty("newValue")
        public String newValue;

    }


    static class VerkleProof {

        @JsonProperty("otherStems")
        public List<String> otherStems;
        @JsonProperty("depthExtensionPresent")
        public String depthExtensionPresent;
        @JsonProperty("commitmentsByPath")
        public List<String> commitmentsByPath;
        @JsonProperty("d")
        public String d;
        @JsonProperty("ipaProof")
        public IpaProof ipaProof;

    }


    static class IpaProof {

        @JsonProperty("cl")
        public List<String> cl;
        @JsonProperty("cr")
        public List<String> cr;
        @JsonProperty("finalEvaluation")
        public String finalEvaluation;

    }
}