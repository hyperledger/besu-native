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
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;


public class PedersenCommitmentTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static List<TestData> JsonData() throws IOException {
        InputStream inputStream = PedersenCommitmentTest.class.getResourceAsStream("/pedersen_commitment_test.json");
        return objectMapper.readValue(inputStream, new TypeReference<List<TestData>>() {});
    }

    static class TestData {
        public ArrayList<String> frs;
        public String commitment;
    }

    @ParameterizedTest
    @MethodSource("JsonData")
    public void TestPolynomialCommitments(TestData testData) {
        Bytes frHeader = Bytes.fromHexString("0xa0");
        List<Bytes> FrBytes = new ArrayList<>();
        for (int i = 0 ; i < 256; i++ ) {
            Bytes32 value = Bytes32.fromHexString(testData.frs.get(i));
            FrBytes.add(Bytes.concatenate(frHeader, value));
        }
        Bytes inHeader = Bytes.fromHexString("0xf92100");
        Bytes inPayload = Bytes.concatenate(FrBytes);
        byte[] input = Bytes.concatenate(inHeader, inPayload).toArray();
        Bytes result = Bytes.wrap(LibIpaMultipoint.toScalar(LibIpaMultipoint.commit(input))).slice(1);
        Bytes expected = Bytes.fromHexString(testData.commitment);
        assertThat(result).isEqualTo(expected);
    }
}
