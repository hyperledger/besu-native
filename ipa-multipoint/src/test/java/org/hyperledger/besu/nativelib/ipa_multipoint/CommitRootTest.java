package org.hyperledger.besu.nativelib.ipa_multipoint;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.nativelib.ipamultipoint.LibIpaMultipoint;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class CommitRootTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static List<TestData> JsonData() throws IOException {
        InputStream inputStream = PedersenCommitmentTest.class.getResourceAsStream("/genesis_lvl1_commits.json");
        return objectMapper.readValue(inputStream, new TypeReference<List<TestData>>() {
        });
    }

    static class TestData {
        public ArrayList<String> frs;
        public String expected;
    }

    @ParameterizedTest
    @MethodSource("JsonData")
    public void TestPolynomialCommitments(TestData testData) {
        List<Bytes> FrBytes = new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            Bytes32 value = Bytes32.fromHexString(testData.frs.get(i));
            FrBytes.add(value);
        }
        byte[] input = Bytes.concatenate(FrBytes).toArray();
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commitRoot(input));
        Bytes32 expected = Bytes32.fromHexString(testData.expected);
        assertThat(result).isEqualTo(expected);
    }
}
