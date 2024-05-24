package org.hyperledger.besu.nativelib.ipa_multipoint.proof;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.nativelib.ipamultipoint.LibIpaMultipoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

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
        final List<byte[]> allNewValues = new ArrayList<>();
        executionWitnessData.executionWitness.stateDiff.forEach(stateDiff -> {
            Bytes stem = Bytes.fromHexString(stateDiff.stem);
            stateDiff.suffixDiffs.forEach(suffixDiff -> {
                allStemsKeys.add(Bytes.concatenate(stem,Bytes.of(suffixDiff.suffix)).toArrayUnsafe());
                allCurrentValues.add(((suffixDiff.currentValue==null)?Bytes.EMPTY:Bytes.fromHexString(suffixDiff.currentValue)).toArrayUnsafe());
                allNewValues.add(((suffixDiff.newValue==null)?Bytes.EMPTY:Bytes.fromHexString(suffixDiff.newValue)).toArrayUnsafe());
            });
        });
        final byte[][] commitmentsByPath = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.commitmentsByPath);
        final byte[][] allCl = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cl);
        final byte[][] allCr = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cr);
        final byte[][] allOtherStems = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.otherStems);
        final byte[] d = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.d).toArrayUnsafe();
        final byte[] depthExtensionPresent = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.depthExtensionPresent).toArrayUnsafe();
        final byte[] finalEvaluation = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.ipaProof.finalEvaluation).toArrayUnsafe();

        return LibIpaMultipoint.verifyPreStateRoot(allStemsKeys.toArray(byte[][]::new), allCurrentValues.toArray(byte[][]::new), allNewValues.toArray(byte[][]::new), commitmentsByPath, allCl, allCr, allOtherStems, d, depthExtensionPresent, finalEvaluation, preStateRoot.toArrayUnsafe());
    }


    private static byte[][] convertListToByte2DArray(List<String> list) {
        byte[][] array = new byte[list.size()][];
        for (int i = 0; i < list.size(); i++) {
            array[i] = Bytes.fromHexString(list.get(i)).toArrayUnsafe();
        }
        return array;
    }

}
