package org.hyperledger.besu.nativelib.constantine;

import com.google.common.collect.Streams;
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
public class ConstantineEIP2537PairingCheckTest {

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
        return
            Streams.concat(
                    CharStreams.readLines(
                            new InputStreamReader(
                                ConstantineEIP2537PairingCheckTest.class.getResourceAsStream("/pairing.csv"),
                                UTF_8))
                        .stream(),
                    CharStreams.readLines(
                            new InputStreamReader(
                                ConstantineEIP2537PairingCheckTest.class.getResourceAsStream(
                                    "/invalid_pairing.csv"),
                                UTF_8))
                        .stream())
                .filter(line -> !line.startsWith("#"))
                .map(line -> line.split(",", 4))
                .collect(Collectors.toList());
    }

    @Test
    public void shouldCalculatePairingCheck() {
        if ("input".equals(input)) {
            // skip the header row
            return;
        }

        byte[] inputBytes = Bytes.fromHexString(this.input).toArrayUnsafe();

        // Allocate buffer for the result of pairing check, expected to be 32 bytes for BLS12-381 pairing check
        byte[] result = new byte[32];

        // Call the native Pairing Check function for EIP2537
        int status = LibConstantineEIP2537.bls12381_pairingCheck(result, result.length, inputBytes, inputBytes.length);

        // Convert the expected result to Bytes object
        Bytes expectedComputation = expectedResult == null ? null : Bytes.fromHexString(expectedResult);

        // Check the status and result based on the computation
        if (status != 0) {
            assertNotNull("Notes should not be empty", notes);  // Check if error notes are present
            assertNotEquals("Status should not be success", 0, status);  // Ensure the status is not success
            assertArrayEquals("Result should be empty on failure", new byte[32], result);  // Ensure result is empty on failure
        } else {
            // If the status is 0 (success), wrap the result in a Bytes object and compare with expected result
            Bytes actualComputation = Bytes.wrap(result);
//            if (actualComputation.isZero()) actualComputation = Bytes.EMPTY;  // Handle zero computation

            assertEquals("Computed result should match expected result", expectedComputation, actualComputation);  // Ensure result matches
            assertTrue("Notes should be empty on success", notes.isEmpty());  // Ensure no notes on success
        }
    }
}
