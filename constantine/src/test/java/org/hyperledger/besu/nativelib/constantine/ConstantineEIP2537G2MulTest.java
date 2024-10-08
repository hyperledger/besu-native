package org.hyperledger.besu.nativelib.constantine;

import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class ConstantineEIP2537G2MulTest {

    @Parameterized.Parameter(0)
    public String input;
    @Parameterized.Parameter(1)
    public String expectedResult;
    @Parameterized.Parameter(2)
    public String expectedGasUsed;
    @Parameterized.Parameter(3)
    public String notes;

    @Parameterized.Parameters
    public static Iterable<String[]> parameters() throws IOException {
        return CharStreams.readLines(
                        new InputStreamReader(
                                ConstantineEIP2537G2MulTest.class.getResourceAsStream("/g2_mul.csv"), UTF_8))
                .stream()
                .map(line -> line.split(",", 4))
                .collect(Collectors.toList());
    }

    @Test
    public void shouldCalculate() {
        if ("input".equals(input)) {
            return;  // skip header row
        }

        byte[] inputBytes = Bytes.fromHexString(this.input).toArrayUnsafe();
        byte[] result = new byte[192];  // G2 element is 192 bytes in BLS12-381

        int status = LibConstantineEIP2537.bls12381_g2mul(result, result.length, inputBytes, inputBytes.length);

        Bytes expectedComputation = expectedResult == null ? null : Bytes.fromHexString(expectedResult);
        if (status != 0) {
            assertNotNull("Notes should not be empty", notes);
            assertNotEquals("Status should not be success", 0, status);
            assertArrayEquals("Result should be empty on failure", new byte[192], result);
        } else {
            Bytes actualComputation = Bytes.wrap(result);
            if (actualComputation.isZero()) actualComputation = Bytes.EMPTY;

            assertEquals("Computed result should match expected result", expectedComputation, actualComputation);
            assertTrue("Notes should be empty on success", notes.isEmpty());
        }
    }
}
