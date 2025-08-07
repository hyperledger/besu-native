/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package main

import (
    "bufio"
    "os"
    "strconv"
    "strings"
    "encoding/hex"
    "fmt"
    "math/big"
    "math/rand"
    "github.com/consensys/gnark-crypto/ecc/bn254"
    bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"

    "github.com/consensys/gnark-crypto/ecc/bls12-381"
    blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// return bls12-381 g2 generator point in jacobian form
func g2GeneratorPoint() (*bls12381.G2Jac){
    var g2Gen bls12381.G2Jac
    g2Gen.X.SetString("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160",
          "3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758")
    g2Gen.Y.SetString("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905",
          "927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582")
     g2Gen.Z.SetString("1", "0")
    return &g2Gen
}


// blsGenerateTestDataForMulG1 generates input data suitable for bls12-381 G1 multi-scalar multiplication.
// iter specifcies the number of point/scalar combinations
func blsGenerateTestDataForG1MSM(iter int) {
    for i := 0; i < iter; i++ {
        // Generate a random fp.Element
        var a blsfp.Element
        a.SetRandom()

        // Map the random element to a G1 point
        g := bls12381.MapToG1(a)

        // Generate a random scalar
        randScalar, _ := GenerateRandomUint256()

        // Print the G1 point and scalar
        fmt.Printf("%s%s%s", blsFpElementToHex(g.X), blsFpElementToHex(g.Y), Uint256ToStringBigEndian(randScalar))

    }
}

// blsGenerateTestDataForMulG2 generates input data suitable for bls12-381 G2 multi-scalar multiplication.
// iter specifcies the number of point/scalar combinations
func blsGenerateTestDataForG2MSM(iter int) {
    // use the generator point as the starting point:
    randomG2Jac := g2GeneratorPoint();

    for i := 0; i < iter; i++ {

        // Generate random G2 affine
        randomG2Jac, _  := RandomG2PointGenerator(randomG2Jac)
        var randomG2Affine bls12381.G2Affine
        randomG2Affine.FromJacobian(randomG2Jac)

        // Generate a random scalar
        randScalar, _ := GenerateRandomUint256()

        // Print the G2 point and scalar
        fmt.Printf("%s%s%s%s%s",
                   blsFpElementToHex(randomG2Affine.X.A0),
                   blsFpElementToHex(randomG2Affine.X.A1),
                   blsFpElementToHex(randomG2Affine.Y.A0),
                   blsFpElementToHex(randomG2Affine.Y.A1),
                   Uint256ToStringBigEndian(randScalar))

    }
}

// blsFpElementToHex converts a 48 byte bls12-381 fp.Element to a 64-byte zero-prepended hex string
func blsFpElementToHex(e blsfp.Element) string {
    // Convert fp.Element to big.Int
    bigInt := new(big.Int)
    e.BigInt(bigInt)
    return fmt.Sprintf("%0128x", bigInt)
}

// GenerateRandomUint256 generates a random 32-byte unsigned number.
func GenerateRandomUint256() (*big.Int, error) {
    bytes := make([]byte, 32)
    _, err := rand.Read(bytes)
    if err != nil {
        return nil, err
    }
    number := new(big.Int).SetBytes(bytes)
    return number, nil
}

// RandomG2PointGenerator performs a multiplication by a random scalar to generate a "random" point
func RandomG2PointGenerator(from *bls12381.G2Jac) (*bls12381.G2Jac, error) {

    // Generate a random scalar
    randomScalar, err := GenerateRandomUint256()
    if err != nil {
        return nil, err
    }

    // Multiply the generator by the random scalar
    var result bls12381.G2Jac
    result.ScalarMultiplication(from, randomScalar)
    return &result, nil
}

// Uint256ToStringBigEndian serializes a 32-byte unsigned number to a string in big-endian format.
func Uint256ToStringBigEndian(number *big.Int) string {
    bytes := number.FillBytes(make([]byte, 32))
    return hex.EncodeToString(bytes)
}

// generate g1Add test data cases suitable for unit test input csv
func bn254GenerateTestDataForG1AddCSV(iter int) {
    // generate a point from a field element

    for i := 0 ; i < iter; i++ {
        a := bn254fp.NewElement(rand.Uint64())
        b := bn254fp.NewElement(rand.Uint64())
        g := bn254.MapToG1(a)
        gg := bn254.MapToG1(b)
        fmt.Printf("%032x%032x",
            g.Marshal(),
            gg.Marshal())
        res := g.Add(&g, &gg)
        fmt.Printf(",%032x,500,\n", res.Marshal())
    }
}

// generate bn254 g1Mul test data cases suitable for unit test input csv file
func bn254GenerateTestDataForG1MulCSV(iter int) {
    // generate test data
    //var p, res1, res2 bn254.G1Jac
    var a = bn254fp.NewElement(0)

    for i := 0 ; i < iter ; i++ {
        a.SetRandom()
        randScalar, _ := GenerateRandomUint256()

        g := bn254.MapToG1(a)
        fmt.Printf("%032x%s",
          g.Marshal(),
          Uint256ToStringBigEndian(randScalar))

        res := g.ScalarMultiplication(&g, randScalar)
        fmt.Printf(",%032x,40000,\n",
          res.Marshal())
    }
}

func main() {
    reader := bufio.NewReader(os.Stdin)

    for {
        // Display available commands
        fmt.Println("\nAvailable commands:")
        fmt.Println("\teip2537_g1msm <iter>  generate bls12-381 precompile G1 MSM input data for <iter> point/scalar combinations")
        fmt.Println("\teip2537_g2msm <iter>  generate bls12-381 precompile G2 MSM input data for <iter> point/scalar combinations")
        fmt.Println("\teip196_g1add <lines>  generate <lines> lines unit test CSV random input for bn254 G1 add precompile")
        fmt.Println("\teip196_g1mul <lines>  generate <lines> lines unit test CSV random input for bn254 G1 mul precompile")
        fmt.Println("\texit                  quit the test data generator app")
        fmt.Print("Enter command: ")

        // Read user input
        input, _ := reader.ReadString('\n')
        input = strings.TrimSpace(input)

        // Convert input to lowercase for case-insensitive comparison
        input = strings.ToLower(input)

        // Handle exit
        if input == "exit" {
            fmt.Println("Exiting...")
            break
        }

        // Parse the command and argument
        args := strings.Split(input, " ")
        if len(args) < 2 {
            fmt.Println("Invalid input, please provide a command and iteration count.")
            continue
        }
        command := args[0]
        iterations, err := strconv.Atoi(args[1])
        if err != nil {
            fmt.Println("Invalid iteration count, must be a number.")
            continue
        }

        // Call the corresponding function based on the command
        switch command {
        case "eip2537_g1msm":
            fmt.Printf("\nGenerating bls12-381 G1 msm test point (%d iterations):\n", iterations)
            blsGenerateTestDataForG1MSM(iterations)
        case "eip2537_g2msm":
            fmt.Printf("\nGenerating bls12-381 G2 msm test point (%d iterations):\n", iterations)
            blsGenerateTestDataForG2MSM(iterations)
        case "eip196_g1add":
            fmt.Printf("\nGenerating bn254 G1 add test data (%d lines):\n", iterations)
            bn254GenerateTestDataForG1AddCSV(iterations)
        case "eip196_g1mul":
            fmt.Printf("\nGenerating bn254 G1 mul test data (%d lines):\n", iterations)
            bn254GenerateTestDataForG1MulCSV(iterations)
        default:
            fmt.Println("Unknown command:", command)
        }
    }
}
