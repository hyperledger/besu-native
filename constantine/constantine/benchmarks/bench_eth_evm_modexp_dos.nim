import
  constantine/ethereum_evm_precompiles,
  constantine/math/arithmetic,
  constantine/math/io/io_bigints,
  constantine/platforms/abstractions,
  ./bench_blueprint

proc report(op: string, elapsedNs: int64, elapsedCycles: int64, iters: int) =
  let ns = elapsedNs div iters
  when SupportsGetTicks:
    let cycles = elapsedCycles div iters
  let throughput = 1e9 / float64(ns)
  when SupportsGetTicks:
    echo &"{op:<70} {throughput:>15.3f} ops/s {ns:>16} ns/op {cycles:>12} CPU cycles (approx)"
  else:
    echo &"{op:<70} {throughput:>15.3f} ops/s {ns:>16} ns/op"

template bench(fnCall: untyped, ticks, ns: var int64): untyped =
  block:
    let startTime = getMonotime()
    when SupportsGetTicks:
      let startClock = getTicks()
    fnCall
    when SupportsGetTicks:
      let stopClock = getTicks()
    let stopTime = getMonotime()

    when SupportsGetTicks:
      ticks += stopClock - startClock
    ns += inNanoseconds(stopTime-startTime)

func computeGasFee(inputs: openArray[byte]): tuple[eip128, eip2565: int] =
  ## Note: This is an approximation
  # For Denial-of-Service fuzzing we want to ensure that
  # 30M gas blocks are processed in a few milliseconds at most
  # https://eips.ethereum.org/EIPS/eip-198
  # https://eips.ethereum.org/EIPS/eip-2565
  func mulComplexityEIP198(x: int): int =
    ## Estimates the difficulty of Karatsuba multiplication
    if x <= 64: x * x
    elif x <= 1024: (x * x) div 4 + 96*x - 3072
    else: (x * x) div 16 + 480*x - 199680

  func mulComplexityEIP2565(x: int): int =
    result = (x+7) div 8
    result *= result

  func getMSB_bigEndian(a: openArray[byte]): int =
    ## Returns the position of the most significant bit
    ## of `a`.
    ## Returns 0 if a == 0
    ##
    ## a is stored in bigEndian representation
    result = 0
    for i in 0 ..< a.len:
      if a[i] != byte(0):
        return int(log2_vartime(uint32 a[i])) + 8*(a.len-1-i)

  func iterCount(exponent: openArray[byte]): int =
    let msbFirst32Bits = exponent.toOpenArray(0, min(exponent.len, 32) - 1).getMSB_bigEndian()

    if exponent.len <= 32:
      result = msbFirst32Bits
    else:
      result = (8*(exponent.len-32)) + msbFirst32Bits
    if result < 1:
      result = 1

  func gasCostEIP198(baseLen, modLen: int, exponent: openArray[byte]): int =
    const Gquaddivisor = 20
    let mulComplexity = mulComplexityEIP198(max(baseLen, modLen))
    let adjExpLen = iterCount(exponent)

    return (mulComplexity * max(adjExpLen, 1)) div Gquaddivisor

  func gasCostEIP2565(baseLen, modLen: int, exponent: openArray[byte]): int =
    const Gquaddivisor = 3
    let mulComplexity = mulComplexityEIP2565(max(baseLen, modLen))
    let iterCount = iterCount(exponent)

    return max(200, (mulComplexity * iterCount) div Gquaddivisor)

  # Input parse sizes
  # -----------------
  let
    bL = BigInt[256].unmarshal(inputs.toOpenArray(0, 31), bigEndian)
    eL = BigInt[256].unmarshal(inputs.toOpenArray(32, 63), bigEndian)
    mL = BigInt[256].unmarshal(inputs.toOpenArray(64, 95), bigEndian)

    baseByteLen = cast[int](bL.limbs[0])
    exponentByteLen = cast[int](eL.limbs[0])
    modulusByteLen = cast[int](mL.limbs[0])

    baseStart = 96
    baseStop  = baseStart+baseByteLen-1
    expStart  = baseStop+1
    expStop   = expStart+exponentByteLen-1
    # modStart  = expStop+1
    # modStop   = modStart+modulusByteLen-1

  template exponent(): untyped =
    inputs.toOpenArray(expStart, expStop)

  let gasFeeEIP198 = gasCostEIP198(baseByteLen, modulusByteLen, exponent)
  let gasFeeEIP2565 = gasCostEIP2565(baseByteLen, modulusByteLen, exponent)

  return (gasFeeEIP198, gasFeeEIP2565)

proc dos1() =

  let input = [
      # Length of base (32)
      uint8 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,

      # Length of exponent (32)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,

      # Length of modulus (32)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,

      # Base (96064778440517843452771003943013638877275214272712651271554889917016327417616)
      0xd4, 0x62, 0xbc, 0xde, 0x8f, 0x57, 0xb0, 0x4a, 0x3f, 0xe1, 0x16, 0xc8, 0x12, 0x8c, 0x44, 0x34,
      0xcf, 0x10, 0x25, 0x2e, 0x48, 0xa3, 0xcc, 0x0d, 0x28, 0xdf, 0x2b, 0xac, 0x4a, 0x8d, 0x6f, 0x10,

      # Exponent (96064778440517843452771003943013638877275214272712651271554889917016327417616)
      0xd4, 0x62, 0xbc, 0xde, 0x8f, 0x57, 0xb0, 0x4a, 0x3f, 0xe1, 0x16, 0xc8, 0x12, 0x8c, 0x44, 0x34,
      0xcf, 0x10, 0x25, 0x2e, 0x48, 0xa3, 0xcc, 0x0d, 0x28, 0xdf, 0x2b, 0xac, 0x4a, 0x8d, 0x6f, 0x10,

      # Modulus (57896044618658097711785492504343953926634992332820282019728792003956564819968)
      0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]

  var r = newSeq[byte](32)
  var ticks, nanoseconds: int64

  let (gasFeeEIP198, gasFeeEIP2565) = computeGasFee(input)
  const blockSize = 30000000

  let execsEIP198 = blockSize div gasFeeEIP198
  let execsEIP2565 = blockSize div gasFeeEIP2565

  echo "Gas cost: ", gasFeeEIP198, " gas (EIP-198) - ", execsEIP198, " executions per block"
  echo "Gas cost: ", gasFeeEIP2565, " gas (EIP-2565) - ", execsEIP2565, " executions per block"

  for i in 0 ..< execsEIP2565:
      bench(
        (let _ = r.eth_evm_modexp(input)),
        ticks, nanoseconds)

  report("EVM Modexp - 32,32,32 - even base & power-of-2 modulus", nanoseconds, ticks, execsEIP2565)
  echo "Total time: ", nanoseconds.float64 / 1e6, " ms for ", execsEIP2565, " iterations"

proc dos2() =

  let input = [
    # Length of base (1)
    uint8 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of exponent (1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of modulus (121)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79,

    # Base
    0x33,

    # Exponent
    0x01,

    # Modulus
    0x04, 0xea, 0xbb, 0x12, 0x55, 0x88, 0xd7, 0x3c, 0xad, 0x22, 0xea, 0x2b, 0x4a, 0x77, 0x6e, 0x9d,
    0x4d, 0xfc, 0x13, 0xa8, 0x1b, 0xf9, 0x0c, 0x0d, 0x37, 0xe8, 0x4e, 0x8b, 0xeb, 0xb2, 0xa5, 0x48,
    0x8b, 0x2c, 0x87, 0x6d, 0x13, 0x51, 0x75, 0xeb, 0x97, 0xc6, 0x13, 0xd9, 0x06, 0xce, 0x8b, 0x53,
    0xd0, 0x02, 0x68, 0xb8, 0xd6, 0x12, 0xab, 0x8b, 0x15, 0x0c, 0xef, 0x0a, 0xd0, 0x3b, 0x73, 0xd2,
    0xdb, 0x9d, 0x2a, 0xa5, 0x23, 0x70, 0xdc, 0x26, 0x55, 0x80, 0xca, 0xf2, 0xc0, 0x18, 0xe3, 0xe3,
    0x1b, 0xad, 0xd5, 0x22, 0xdd, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1c, 0x05, 0x71, 0x52, 0x7c, 0x3a, 0xb0, 0x77,
  ]

  var r = newSeq[byte](121)
  var ticks, nanoseconds: int64

  let (gasFeeEIP198, gasFeeEIP2565) = computeGasFee(input)
  const blockSize = 30000000

  let execsEIP198 = blockSize div gasFeeEIP198
  let execsEIP2565 = blockSize div gasFeeEIP2565

  echo "Gas cost: ", gasFeeEIP198, " gas (EIP-198) - ", execsEIP198, " executions per block"
  echo "Gas cost: ", gasFeeEIP2565, " gas (EIP-2565) - ", execsEIP2565, " executions per block"

  for i in 0 ..< execsEIP2565:
      bench(
        (let _ = r.eth_evm_modexp(input)),
        ticks, nanoseconds)

  report("EVM Modexp - 1,1,121 - exponent=1 and odd modulus", nanoseconds, ticks, execsEIP2565)
  echo "Total time: ", nanoseconds.float64 / 1e6, " ms for ", execsEIP2565, " iterations"

proc dos2a() =
  # shortcuttable variation with even modulus

  let input = [
    # Length of base (1)
    uint8 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of exponent (1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of modulus (121)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79,

    # Base
    0x33,

    # Exponent
    0x01,

    # Modulus
    0x04, 0xea, 0xbb, 0x12, 0x55, 0x88, 0xd7, 0x3c, 0xad, 0x22, 0xea, 0x2b, 0x4a, 0x77, 0x6e, 0x9d,
    0x4d, 0xfc, 0x13, 0xa8, 0x1b, 0xf9, 0x0c, 0x0d, 0x37, 0xe8, 0x4e, 0x8b, 0xeb, 0xb2, 0xa5, 0x48,
    0x8b, 0x2c, 0x87, 0x6d, 0x13, 0x51, 0x75, 0xeb, 0x97, 0xc6, 0x13, 0xd9, 0x06, 0xce, 0x8b, 0x53,
    0xd0, 0x02, 0x68, 0xb8, 0xd6, 0x12, 0xab, 0x8b, 0x15, 0x0c, 0xef, 0x0a, 0xd0, 0x3b, 0x73, 0xd2,
    0xdb, 0x9d, 0x2a, 0xa5, 0x23, 0x70, 0xdc, 0x26, 0x55, 0x80, 0xca, 0xf2, 0xc0, 0x18, 0xe3, 0xe3,
    0x1b, 0xad, 0xd5, 0x22, 0xdd, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1c, 0x05, 0x71, 0x52, 0x7c, 0x3a, 0xb0, 0x76,
  ]

  var r = newSeq[byte](121)
  var ticks, nanoseconds: int64

  let (gasFeeEIP198, gasFeeEIP2565) = computeGasFee(input)
  const blockSize = 30000000

  let execsEIP198 = blockSize div gasFeeEIP198
  let execsEIP2565 = blockSize div gasFeeEIP2565

  echo "Gas cost: ", gasFeeEIP198, " gas (EIP-198) - ", execsEIP198, " executions per block"
  echo "Gas cost: ", gasFeeEIP2565, " gas (EIP-2565) - ", execsEIP2565, " executions per block"

  for i in 0 ..< execsEIP2565:
      bench(
        (let _ = r.eth_evm_modexp(input)),
        ticks, nanoseconds)

  report("EVM Modexp - 1,1,121 - exponent=1 and even modulus", nanoseconds, ticks, execsEIP2565)
  echo "Total time: ", nanoseconds.float64 / 1e6, " ms for ", execsEIP2565, " iterations"

proc dos2b() =
  # even variation with no shortcut

  let input = [
    # Length of base (1)
    uint8 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of exponent (1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of modulus (121)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79,

    # Base
    0x33,

    # Exponent
    0x10,

    # Modulus
    0x04, 0xea, 0xbb, 0x12, 0x55, 0x88, 0xd7, 0x3c, 0xad, 0x22, 0xea, 0x2b, 0x4a, 0x77, 0x6e, 0x9d,
    0x4d, 0xfc, 0x13, 0xa8, 0x1b, 0xf9, 0x0c, 0x0d, 0x37, 0xe8, 0x4e, 0x8b, 0xeb, 0xb2, 0xa5, 0x48,
    0x8b, 0x2c, 0x87, 0x6d, 0x13, 0x51, 0x75, 0xeb, 0x97, 0xc6, 0x13, 0xd9, 0x06, 0xce, 0x8b, 0x53,
    0xd0, 0x02, 0x68, 0xb8, 0xd6, 0x12, 0xab, 0x8b, 0x15, 0x0c, 0xef, 0x0a, 0xd0, 0x3b, 0x73, 0xd2,
    0xdb, 0x9d, 0x2a, 0xa5, 0x23, 0x70, 0xdc, 0x26, 0x55, 0x80, 0xca, 0xf2, 0xc0, 0x18, 0xe3, 0xe3,
    0x1b, 0xad, 0xd5, 0x22, 0xdd, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1c, 0x05, 0x71, 0x52, 0x7c, 0x3a, 0xb0, 0x77,
  ]

  var r = newSeq[byte](121)
  var ticks, nanoseconds: int64

  let (gasFeeEIP198, gasFeeEIP2565) = computeGasFee(input)
  const blockSize = 30000000

  let execsEIP198 = blockSize div gasFeeEIP198
  let execsEIP2565 = blockSize div gasFeeEIP2565

  echo "Gas cost: ", gasFeeEIP198, " gas (EIP-198) - ", execsEIP198, " executions per block"
  echo "Gas cost: ", gasFeeEIP2565, " gas (EIP-2565) - ", execsEIP2565, " executions per block"

  for i in 0 ..< execsEIP2565:
      bench(
        (let _ = r.eth_evm_modexp(input)),
        ticks, nanoseconds)

  report("EVM Modexp - 1,1,121 - exponent=16 and odd modulus", nanoseconds, ticks, execsEIP2565)
  echo "Total time: ", nanoseconds.float64 / 1e6, " ms for ", execsEIP2565, " iterations"

proc dos2c() =
  # odd variation with no shortcut

  let input = [
    # Length of base (1)
    uint8 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of exponent (1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of modulus (121)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79,

    # Base
    0x33,

    # Exponent
    0x07,

    # Modulus
    0x04, 0xea, 0xbb, 0x12, 0x55, 0x88, 0xd7, 0x3c, 0xad, 0x22, 0xea, 0x2b, 0x4a, 0x77, 0x6e, 0x9d,
    0x4d, 0xfc, 0x13, 0xa8, 0x1b, 0xf9, 0x0c, 0x0d, 0x37, 0xe8, 0x4e, 0x8b, 0xeb, 0xb2, 0xa5, 0x48,
    0x8b, 0x2c, 0x87, 0x6d, 0x13, 0x51, 0x75, 0xeb, 0x97, 0xc6, 0x13, 0xd9, 0x06, 0xce, 0x8b, 0x53,
    0xd0, 0x02, 0x68, 0xb8, 0xd6, 0x12, 0xab, 0x8b, 0x15, 0x0c, 0xef, 0x0a, 0xd0, 0x3b, 0x73, 0xd2,
    0xdb, 0x9d, 0x2a, 0xa5, 0x23, 0x70, 0xdc, 0x26, 0x55, 0x80, 0xca, 0xf2, 0xc0, 0x18, 0xe3, 0xe3,
    0x1b, 0xad, 0xd5, 0x22, 0xdd, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1c, 0x05, 0x71, 0x52, 0x7c, 0x3a, 0xb0, 0x77,
  ]

  var r = newSeq[byte](121)
  var ticks, nanoseconds: int64

  let (gasFeeEIP198, gasFeeEIP2565) = computeGasFee(input)
  const blockSize = 30000000

  let execsEIP198 = blockSize div gasFeeEIP198
  let execsEIP2565 = blockSize div gasFeeEIP2565

  echo "Gas cost: ", gasFeeEIP198, " gas (EIP-198) - ", execsEIP198, " executions per block"
  echo "Gas cost: ", gasFeeEIP2565, " gas (EIP-2565) - ", execsEIP2565, " executions per block"

  for i in 0 ..< execsEIP2565:
    bench(
      (let _ = r.eth_evm_modexp(input)),
      ticks, nanoseconds)

  report("EVM Modexp - 1,1,121 - exponent=7 and odd modulus", nanoseconds, ticks, execsEIP2565)
  echo "Total time: ", nanoseconds.float64 / 1e6, " ms for ", execsEIP2565, " iterations"

proc dos2d() =
  # odd variation with no shortcut and power of 2 modulus

  let input = [
    # Length of base (1)
    uint8 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of exponent (1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    # Length of modulus (121)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79,

    # Base
    0x33,

    # Exponent
    0x07,

    # Modulus
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]

  var r = newSeq[byte](121)
  var ticks, nanoseconds: int64

  let (gasFeeEIP198, gasFeeEIP2565) = computeGasFee(input)
  const blockSize = 30000000

  let execsEIP198 = blockSize div gasFeeEIP198
  let execsEIP2565 = blockSize div gasFeeEIP2565

  echo "Gas cost: ", gasFeeEIP198, " gas (EIP-198) - ", execsEIP198, " executions per block"
  echo "Gas cost: ", gasFeeEIP2565, " gas (EIP-2565) - ", execsEIP2565, " executions per block"

  for i in 0 ..< execsEIP2565:
    bench(
      (let _ = r.eth_evm_modexp(input)),
      ticks, nanoseconds)

  report("EVM Modexp - 1,1,121 - exponent=7 and power-of-2 modulus", nanoseconds, ticks, execsEIP2565)
  echo "Total time: ", nanoseconds.float64 / 1e6, " ms for ", execsEIP2565, " iterations"

dos1()
echo "\n"
dos2()
echo "\n"
dos2a()
echo "\n"
dos2b()
echo "\n"
dos2c()
echo "\n"
dos2d()
