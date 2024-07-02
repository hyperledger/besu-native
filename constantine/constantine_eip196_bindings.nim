# constantine_eip196_bindings.nim
import "./constantine/constantine/ethereum_evm_precompiles"

type
  CttEVMStatus* {.size: sizeof(cint), pure.} = enum
    cttEVM_Success
    cttEVM_InvalidInputSize
    cttEVM_InvalidOutputSize
    cttEVM_IntLargerThanModulus
    cttEVM_PointNotOnCurve
    cttEVM_PointNotInSubgroup


proc eth_evm_bn254_g1add*(r: ptr uint8, rLen: cint, inputs: ptr uint8, inputsLen: cint): CttEVMStatus {.exportc.} =
  var result: seq[byte] = newSeq[byte](rLen)
  var inputSeq: seq[byte] = cast[seq[byte]](inputs[0 ..< inputsLen])
  let status = ethereum_evm_precompiles.eth_evm_bn254_g1add(result, inputSeq)
  copyMem(r, addr result[0], rLen)
  return status

proc eth_evm_bn254_g1mul*(r: ptr uint8, rLen: cint, inputs: ptr uint8, inputsLen: cint): CttEVMStatus {.exportc.} =
  var result: seq[byte] = newSeq[byte](rLen)
  var inputSeq: seq[byte] = cast[seq[byte]](inputs[0 ..< inputsLen])
  let status = ethereum_evm_precompiles.eth_evm_bn254_g1mul(result, inputSeq)
  copyMem(r, addr result[0], rLen)
  return status

proc eth_evm_bn254_ecpairingcheck*(r: ptr uint8, rLen: cint, inputs: ptr uint8, inputsLen: cint): CttEVMStatus {.exportc.} =
  var result: seq[byte] = newSeq[byte](rLen)
  var inputSeq: seq[byte] = cast[seq[byte]](inputs[0 ..< inputsLen])
  let status = ethereum_evm_precompiles.eth_evm_bn254_ecpairingcheck(result, inputSeq)
  copyMem(r, addr result[0], rLen)
  return status

