package org.hyperledger.besu.nativelib.ipa_multipoint.proof;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.nativelib.ipamultipoint.LibIpaMultipoint;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class VerifyProofTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    static {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Test
    public void TestVerifyPreStateRootValidFor1() throws IOException {
        final InputStream inputStream = VerifyProofTest.class.getResourceAsStream("/valid_block_1.json");
        final ExecutionWitnessData executionWitnessData = objectMapper.readValue(inputStream, new TypeReference<>() {
        });
        final Bytes prestateRoot = Bytes.fromHexString("0x1fbf85345a3cbba9a6d44f991b721e55620a22397c2a93ee8d5011136ac300ee");
        assertThat(verifyPreState(executionWitnessData, prestateRoot)).isTrue();
    }

    @Test
    public void TestVerifyPreStateRootValidFor72() throws IOException {
        final InputStream inputStream = VerifyProofTest.class.getResourceAsStream("/valid_block_72.json");
        final ExecutionWitnessData executionWitnessData = objectMapper.readValue(inputStream, new TypeReference<>() {
        });
        final Bytes prestateRoot = Bytes.fromHexString("0x64e1a647f42e5c2e3c434531ccf529e1b3e93363a40db9fc8eec81f492123510");
        assertThat(verifyPreState(executionWitnessData, prestateRoot)).isTrue();
    }

    @Test
    public void TestVerifyPreStateRootNotValidFor72() throws IOException {
        final InputStream inputStream = VerifyProofTest.class.getResourceAsStream("/invalid_block_72.json");
        final ExecutionWitnessData executionWitnessData = objectMapper.readValue(inputStream, new TypeReference<>() {
        });
        final Bytes prestateRoot = Bytes.fromHexString("0x64e1a647f42e5c2e3c434531ccf529e1b3e93363a40db9fc8eec81f492123510");
        assertThat(verifyPreState(executionWitnessData, prestateRoot)).isFalse();
    }

    @Test
    public void TestVerifyPreStateRootValidFor73() throws IOException {
        final InputStream inputStream = VerifyProofTest.class.getResourceAsStream("/valid_block_73.json");
        final ExecutionWitnessData executionWitnessData = objectMapper.readValue(inputStream, new TypeReference<>() {
        });
        final Bytes prestateRoot = Bytes.fromHexString("0x18d1dfcc6ccc6f34d14af48a865895bf34bde7f3571d9ba24a4b98122841048c");
        assertThat(verifyPreState(executionWitnessData, prestateRoot)).isTrue();
    }

    @Test
    public void TestVerifyPreStateRootNotValidFor73() throws IOException {
        final InputStream inputStream = VerifyProofTest.class.getResourceAsStream("/invalid_block_73.json");
        final ExecutionWitnessData executionWitnessData = objectMapper.readValue(inputStream, new TypeReference<>() {
        });
        final Bytes prestateRoot = Bytes.fromHexString("0x18d1dfcc6ccc6f34d14af48a865895bf34bde7f3571d9ba24a4b98122841048c");
        assertThat(verifyPreState(executionWitnessData, prestateRoot)).isFalse();
    }

    private boolean verifyPreState(final ExecutionWitnessData executionWitnessData, final Bytes preStateRoot){
        final List<byte[]> allStemsKeys = new ArrayList<>();
        final List<byte[]> allCurrentValues = new ArrayList<>();
        executionWitnessData.executionWitness.stateDiff.forEach(stateDiff -> {
            Bytes stem = Bytes.fromHexString(stateDiff.stem);
            stateDiff.suffixDiffs.forEach(suffixDiff -> {
                allStemsKeys.add(Bytes.concatenate(stem,Bytes.of(suffixDiff.suffix)).toArrayUnsafe());
                allCurrentValues.add(((suffixDiff.currentValue==null)?Bytes.EMPTY:Bytes.fromHexString(suffixDiff.currentValue)).toArrayUnsafe());
            });
        });
        final byte[][] commitmentsByPath = toArray(executionWitnessData.executionWitness.verkleProof.commitmentsByPath);
        final byte[][] allCl = toArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cl);
        final byte[][] allCr = toArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cr);
        final byte[][] allOtherStems = toArray(executionWitnessData.executionWitness.verkleProof.otherStems);
        final byte[] d = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.d).toArrayUnsafe();
        final byte[] depthExtensionPresent = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.depthExtensionPresent).toArrayUnsafe();
        final byte[] finalEvaluation = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.ipaProof.finalEvaluation).toArrayUnsafe();

        return LibIpaMultipoint.verifyPreStateRoot(allStemsKeys.toArray(byte[][]::new), allCurrentValues.toArray(byte[][]::new), commitmentsByPath, allCl, allCr, allOtherStems, d, depthExtensionPresent, finalEvaluation, preStateRoot.toArrayUnsafe());
    }


    private byte[][] toArray(final List<String> elt){
        return elt.stream().map(Bytes::fromHexString).map(Bytes::toArrayUnsafe).toArray(byte[][]::new);
    }

}
