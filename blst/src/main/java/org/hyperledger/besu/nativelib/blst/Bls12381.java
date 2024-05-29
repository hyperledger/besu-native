package org.hyperledger.besu.nativelib.blst;

import com.google.common.base.Stopwatch;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;
import supranational.blst.Pairing;
import supranational.blst.Scalar;

import java.util.Optional;

public class Bls12381 {

  static final byte[] PAIRING_FALSE = new byte[32];
  static final byte[] PAIRING_TRUE = new byte[32];
  static {
    PAIRING_TRUE[31] = 0x01;
  }

  record G1MulInput(byte[] g1, Scalar s) {
    static G1MulInput unpad(byte[] packedG1Mul) {
      if (packedG1Mul.length != 160) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for G1 Mul");
      }
      byte[] g1 = new byte[96];
      System.arraycopy(packedG1Mul, 16, g1, 0, 48);
      System.arraycopy(packedG1Mul, 80, g1, 48, 48);
      byte[] sBytes = new byte[32];
      System.arraycopy(packedG1Mul, 128, sBytes, 0, 32);
      Scalar s = new Scalar().from_bendian(sBytes);
      return new G1MulInput(g1, s);
    }

    static G1MulInput[] unpadMany(byte[] packedG1MultiExpr) {
      if (packedG1MultiExpr.length % 160 != 0 || packedG1MultiExpr.length == 0) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for G1 MultiExpr");
      }
      int length = packedG1MultiExpr.length / 160;
      G1MulInput[] mulInputs = new G1MulInput[length];

      for (int i =0 ; i < length; i++) {
        byte[] g1 = new byte[96];
        System.arraycopy(packedG1MultiExpr, i * 160 + 16, g1, 0, 48);
        System.arraycopy(packedG1MultiExpr, i * 160 + 80, g1, 48, 48);
        byte[] sBytes = new byte[32];
        System.arraycopy(packedG1MultiExpr, i * 160 + 128, sBytes, 0, 32);
        Scalar s = new Scalar().from_bendian(sBytes);
        mulInputs[i] = new G1MulInput(g1, s);
      }
      return mulInputs;
    }

  }

  record G1AddInput(byte[] g1a, byte[] g1b) {
    static G1AddInput unpadPair(byte[] packedG1Affine) {
      if (packedG1Affine.length != 256) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for G1 Add");
      }
      byte[] g1a = new byte[96];
      System.arraycopy(packedG1Affine, 16, g1a, 0, 48);
      System.arraycopy(packedG1Affine, 80, g1a, 48, 48);
      byte[] g1b = new byte[96];
      System.arraycopy(packedG1Affine, 144, g1b, 0, 48);
      System.arraycopy(packedG1Affine, 208, g1b, 48, 48);
      return new G1AddInput(g1a, g1b);
    }
  }

  public record G1Output(byte[] padded) {
    static G1Output pad(byte[] unpadded) {
      if (unpadded.length != 96) {
        throw new RuntimeException("BLST_ERROR: invalid output parameter length for packed G1");
      }
      byte[] g1Out = new byte[128];
      System.arraycopy(unpadded, 0, g1Out, 16, 48);
      System.arraycopy(unpadded, 48, g1Out, 80, 48);
      return new G1Output(g1Out);
    }
  }

  public record G1Result(G1Output g1Out, Optional<String> optError) {
  }

  record G2MulInput(byte[] g2, Scalar s){
    static G2MulInput unpadPair(byte[] packedG2Mul) {
      if (packedG2Mul.length != 288) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for G2 Mul");
      }
      byte[] g2 = new byte[192];
      System.arraycopy(packedG2Mul, 16, g2, 48, 48);
      System.arraycopy(packedG2Mul, 80, g2, 0, 48);
      System.arraycopy(packedG2Mul, 144, g2, 144, 48);
      System.arraycopy(packedG2Mul, 208, g2, 96, 48);
      byte[] sBytes = new byte[32];
      System.arraycopy(packedG2Mul, 256, sBytes, 0, 32);
      Scalar s = new Scalar().from_bendian(sBytes);
      return new G2MulInput(g2, s);
    }

    static G2MulInput[] unpadMany(byte[] packedG2MultiExpr){
      if (packedG2MultiExpr.length % 288 != 0 || packedG2MultiExpr.length == 0) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for G2 MultiExpr");
      }
      int length = packedG2MultiExpr.length / 288;
      G2MulInput[] mulInputs = new G2MulInput[length];

      for (int i =0 ; i < length; i++) {
        byte[] g2 = new byte[192];
        System.arraycopy(packedG2MultiExpr, i * 288 + 16, g2, 48, 48);
        System.arraycopy(packedG2MultiExpr, i * 288 + 80, g2, 0, 48);
        System.arraycopy(packedG2MultiExpr, i * 288 + 144, g2, 144, 48);
        System.arraycopy(packedG2MultiExpr, i * 288 + 208, g2, 96, 48);
        byte[] sBytes = new byte[32];
        System.arraycopy(packedG2MultiExpr, i * 288 + 256, sBytes, 0, 32);
        Scalar s = new Scalar().from_bendian(sBytes);
        mulInputs[i] = new G2MulInput(g2, s);
      }
      return mulInputs;
    }

  }

  record G2AddInput(byte[] g2a, byte[] g2b) {
    static G2AddInput unpadPair(byte[] packedG2Affine) {
      if (packedG2Affine.length != 512) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for G2 Add");
      }
      byte[] g2a = new byte[192];
      System.arraycopy(packedG2Affine, 16, g2a, 48, 48);
      System.arraycopy(packedG2Affine, 80, g2a, 0, 48);
      System.arraycopy(packedG2Affine, 144, g2a, 144, 48);
      System.arraycopy(packedG2Affine, 208, g2a, 96, 48);
      byte[] g2b = new byte[192];
      System.arraycopy(packedG2Affine, 272, g2b, 48, 48);
      System.arraycopy(packedG2Affine, 336, g2b, 0, 48);
      System.arraycopy(packedG2Affine, 400, g2b, 144, 48);
      System.arraycopy(packedG2Affine, 464, g2b, 96, 48);
      return new G2AddInput(g2a, g2b);
    }
  }

  public record G2Output(byte[] padded) {
    static G2Output pad(byte[] unpadded) {
      if (unpadded.length != 192) {
        throw new RuntimeException("BLST_ERROR: invalid output parameter length for packed G2");
      }
      byte[] g2Out = new byte[256];
      System.arraycopy(unpadded, 0, g2Out, 80, 48);
      System.arraycopy(unpadded, 48, g2Out, 16, 48);
      System.arraycopy(unpadded, 96, g2Out, 208, 48);
      System.arraycopy(unpadded, 144, g2Out, 144, 48);
      return new G2Output(g2Out);
    }
  }

  public record G2Result(G2Output g2Out, Optional<String> optError) {
  }

  public record PairingInput(byte [] g1, byte[] g2) {
    static PairingInput[] parseMany(byte [] packedPairingInput) {
      if (packedPairingInput.length % 384 != 0 || packedPairingInput.length == 0) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for pairing");
      }
      final int len = packedPairingInput.length / 384;
      final PairingInput[] res = new PairingInput[len];
      for (int i = 0; i< len ; i++) {
        byte [] g1 = new byte[96];
        System.arraycopy(packedPairingInput, i * 384 + 16, g1, 0, 48);
        System.arraycopy(packedPairingInput, i * 384 + 80, g1, 48, 48);

        byte [] g2 = new byte[192];
        System.arraycopy(packedPairingInput, i * 384 + 128 + 16, g2, 48, 48);
        System.arraycopy(packedPairingInput, i * 384 + 128 + 80, g2, 0, 48);
        System.arraycopy(packedPairingInput, i * 384 + 128 + 144, g2, 144, 48);
        System.arraycopy(packedPairingInput, i * 384 + 128 + 208, g2, 96, 48);
        res[i] = new PairingInput(g1, g2);
      }
      return res;
    }
  }

  public record PairingResult(byte[] result, Optional<String> optError){}

  public static final Boolean ENABLED = init();

  static boolean init() {
    //load jblst library:
    try {
      Class.forName("supranational.blst.blstJNI");
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }

  /**
   * Add G1 points a and b, return the result.  Check that the result is on the curve, but do not do
   * subgroup checks per EIP-2537.
   *
   * @param packedG1Affines 256 byte array, comprising 2 G1 affines.  Points are 48 bytes, with each
   *                        left padded with 16 bytes, totaling 64 bytes per point.
   * @return g1Result
   */
  public static G1Result g1Add(byte[] packedG1Affines) {
    // do not do subgroup checks on G1ADD according to EIP-2537 spec
    // get P1 points a and b from affine encoding as jacobian coords
    P1 p1a, p1b;
    try {
      var g1AddInput = G1AddInput.unpadPair(packedG1Affines);
      p1a = new P1_Affine(g1AddInput.g1a).to_jacobian();
      p1b = new P1_Affine(g1AddInput.g1b).to_jacobian();
    } catch (Exception ex) {
      return new G1Result(null, Optional.of(ex.getMessage()));
    }

    // add
    P1 res = p1a.add(p1b);

    // convert result to affine and return
    var g1Unpadded = res.to_affine().serialize();
    return new G1Result(G1Output.pad(g1Unpadded), Optional.empty());
  }

  /**
   * Multiply G1 affine by scalar, return the result.  Perform subgroup checks, per EIP-2537.
   *
   * @param packedG1Mul 160 byte array, comprising a G1 affine and 32 bit scalar.  Points are 48
   *                        bytes, with each left padded with 16 bytes, totaling 64 bytes per point.
   * @return g1Result
   */
  public static G1Result g1Mul(byte[] packedG1Mul) {
    // do not do subgroup checks on G1ADD according to EIP-2537 spec
    // get P1 points a and b from affine encoding as jacobian coords
    P1 p1;
    Scalar s;
    try {
      var g1MulInput = G1MulInput.unpad(packedG1Mul);
      var a = new P1_Affine(g1MulInput.g1);
      if (!a.in_group()) {
        return new G1Result(null,
            Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
      }
      p1 = a.to_jacobian();
      s = g1MulInput.s;
    } catch (Exception ex) {
      return new G1Result(null, Optional.of(ex.getMessage()));
    }

    // multiply
    P1 res = p1.mult(s);

    // convert result to affine and return
    var g1Unpadded = res.to_affine().serialize();
    return new G1Result(G1Output.pad(g1Unpadded), Optional.empty());
  }

  /**
   * Multiply G1 affine/scalar pairs, sum, return the result.  Perform subgroup checks, per EIP-2537.
   *
   * @param packedG1MultiExpr byte array, comprising n G1 affine/scalar paris.
   *                          Points are 48 bytes, with each left padded with 16 bytes,
   *                          totaling 64 bytes per point.
   * @return g1Result
   */
  public static G1Result g1MultiExp(byte[] packedG1MultiExpr) {
    // do not do subgroup checks on G1ADD according to EIP-2537 spec
    // get P1 points a and b from affine encoding as jacobian coords
    P1 p1;
    Scalar s;

    try {
      var g1MultiInput = G1MulInput.unpadMany(packedG1MultiExpr);

      var a = new P1_Affine(g1MultiInput[0].g1);
      if (!a.in_group()) {
        return new G1Result(null,
            Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
      }
      p1 = a.to_jacobian();
      s = g1MultiInput[0].s;

      // multiply
      P1 res = p1.mult(s);

      for (int i = 1; i < g1MultiInput.length; i++) {
        a = new P1_Affine(g1MultiInput[i].g1);
        if (!a.in_group()) {
          return new G1Result(null,
              Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
        }
        p1 = a.to_jacobian();
        s = g1MultiInput[i].s;
        res = res.add(p1.mult(s));
      }

      // convert result to affine and return
      var g1Unpadded = res.to_affine().serialize();
      return new G1Result(G1Output.pad(g1Unpadded), Optional.empty());

    } catch (Exception ex) {
      return new G1Result(null, Optional.ofNullable(ex.getMessage()));
    }
  }

  /**
   * Add G2 points a and b, return the result.  Check that the result is on the curve, but do not do
   * subgroup checks per EIP-2537.
   *
   * @param packedG2Affines 512 byte array, comprising 2 G2 affines.  Points are 48 bytes, with each
   *                        left padded with 16 bytes, totaling 64 bytes per point.
   * @return g2Result
   */
  public static G2Result g2Add(byte[] packedG2Affines) {
    // do not do subgroup checks on G2ADD according to EIP-2537 spec
    // get P2 points a and b from affine encoding as jacobian coords
    Stopwatch sw = Stopwatch.createStarted();
    P2 p2a, p2b;
    try {
      var g2AddInput = G2AddInput.unpadPair(packedG2Affines);
      p2a = new P2(g2AddInput.g2a);
      p2b = new P2(g2AddInput.g2b);
    } catch (Exception ex) {
      return new G2Result(null, Optional.of(ex.getMessage()));
    }

    // add
    P2 res = p2a.add(p2b);

    // convert result to affine and return
    var g2Unpadded = res.to_affine().serialize();
    return new G2Result(G2Output.pad(g2Unpadded), Optional.empty());
  }

  /**
   * Multiply G2 affine by scalar, return the result.  Perform subgroup checks, per EIP-2537.
   *
   * @param packedG2Mul 288 byte array, comprising a G2 affine and 32 bit scalar.  Points are 48
   *                        bytes, with each left padded with 16 bytes, totaling 64 bytes per point.
   * @return g2Result
   */
  public static G2Result g2Mul(byte[] packedG2Mul) {
    // do not do subgroup checks on G2ADD according to EIP-2537 spec
    // get P2 points a and b from affine encoding as jacobian coords
    P2 p2;
    G2MulInput g2MulInput = null;
    try {
      g2MulInput = G2MulInput.unpadPair(packedG2Mul);
      p2 = new P2(g2MulInput.g2);
      if (!p2.in_group()) {
        return new G2Result(null,
            Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
      }

    } catch (Exception ex) {
      return new G2Result(null, Optional.of(ex.getMessage()));
    }

    // multiply
    P2 res = p2.mult(g2MulInput.s);

    // convert result to affine and return
    var g2Unpadded = res.to_affine().serialize();
    return new G2Result(G2Output.pad(g2Unpadded), Optional.empty());
  }

  /**
   * Multiply G2 affine/scalar pairs, sum, return the result.  Perform subgroup checks, per EIP-2537.
   *
   * @param packedG2MultiExpr byte array, comprising a G2 affine and scalar paris.  Points are 48
   *                        bytes, with each left padded with 16 bytes, totaling 64 bytes per point.
   * @return g2Result
   */
  public static G2Result g2MultiExpr(byte[] packedG2MultiExpr) {
    // do not do subgroup checks on G2ADD according to EIP-2537 spec
    // get P2 points a and b from affine encoding as jacobian coords
    P2 p2, res;
    try {

      var g2MulInput = G2MulInput.unpadMany(packedG2MultiExpr);
      res = new P2(g2MulInput[0].g2).mult(g2MulInput[0].s);
      if (!res.in_group()) {
        return new G2Result(null,
            Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
      }

      for(int i = 1; i < g2MulInput.length; i++) {
        // multiply

        p2 = new P2(g2MulInput[i].g2);
        if (!p2.in_group()) {
          return new G2Result(null,
              Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
        }

        res = res.add(p2.mult(g2MulInput[i].s));
      }
    } catch (Exception ex) {
      return new G2Result(null, Optional.of(ex.getMessage()));
    }

    // convert result to affine and return
    var g2Unpadded = res.to_affine().serialize();
    return new G2Result(G2Output.pad(g2Unpadded), Optional.empty());
  }

  public static PairingResult blsPairing(byte[] packedPairing) {
    try {
      final PairingInput[] pairs = PairingInput.parseMany(packedPairing);
      P1_Affine p1;
      P2_Affine p2;
      Pairing res = new Pairing(true, "");
      for (int i = 0; i < pairs.length; i++) {
        p1 = new P1_Affine(pairs[i].g1);
        if (!p1.in_group()) {
          return new PairingResult(PAIRING_FALSE,
              Optional.of("BLST_ERROR: G1 Point is not in the expected subgroup"));
        }
        p2 = new P2_Affine(pairs[i].g2);
        if (!p2.in_group()) {
          return new PairingResult(PAIRING_FALSE,
              Optional.of("BLST_ERROR: G2 Point is not in the expected subgroup"));
        }
        res.raw_aggregate(p2, p1);
      }
      res.commit();
      return new PairingResult(
          res.finalverify() ? PAIRING_TRUE : PAIRING_FALSE, Optional.empty());
    } catch (Exception ex) {
      return new PairingResult(PAIRING_FALSE, Optional.of(ex.getMessage()));
    }
  }

  public static G1Output mapFpToG1(byte[] packedFp1) {
    return null;
  }

  public static G2Output mapFp2ToG2(byte[] packedFp2) {
    return null;
  }
}
