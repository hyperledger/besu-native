package org.hyperledger.besu.nativelib.ipa_multipoint.proof;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.nativelib.ipa_multipoint.PedersenCommitmentTest;
import org.hyperledger.besu.nativelib.ipamultipoint.LibIpaMultipoint;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class VerifyProofTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static ExecutionWitnessData JsonData() throws IOException {
        InputStream inputStream = VerifyProofTest.class.getResourceAsStream("/block72.json");
        return objectMapper.readValue(inputStream, new TypeReference<ExecutionWitnessData>() {});
    }


    @ParameterizedTest
    @MethodSource("JsonData")
    public void TestVerifyPreStateRoot72(ExecutionWitnessData executionWitnessData) {
        byte[][] allStemsKeys = {}; //TODO
        byte[][] allCurrentValues = {}; //TODO
        byte[][] allNewValues = {}; //TODO
        byte[][] commitmentsByPath = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.commitmentsByPath);
        byte[][] allCl = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cl);
        byte[][] allCr = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cr);
        byte[][] allOtherStems = convertListToByte2DArray(executionWitnessData.executionWitness.verkleProof.otherStems);
        byte[] d = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.d).toArrayUnsafe();
        byte[] depthExtensionPresent = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.depthExtensionPresent).toArrayUnsafe();
        byte[] finalEvaluation = Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.ipaProof.finalEvaluation).toArrayUnsafe();
        byte[] prestateRoot = Bytes.fromHexString("0x64e1a647f42e5c2e3c434531ccf529e1b3e93363a40db9fc8eec81f492123510").toArrayUnsafe();

        LibIpaMultipoint.verifyPreStateRoot(allStemsKeys, allCurrentValues, allNewValues, commitmentsByPath, allCl, allCr, allOtherStems, d, depthExtensionPresent, finalEvaluation, prestateRoot);

    }


    private static byte[][] convertListToByte2DArray(List<String> list) {
        byte[][] array = new byte[list.size()][];
        for (int i = 0; i < list.size(); i++) {
            array[i] = Bytes.fromHexString(list.get(i)).toArrayUnsafe();
        }
        return array;
    }

}
