package org.hyperledger.besu.nativelib.blst;

//import com.google.common.base.Stopwatch;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;
import supranational.blst.Scalar;

import java.util.Optional;

public class Bls12381 {

  record G1MultiInput(G1MulInput[] multiInputs) {
    static G1MultiInput unpad(byte[] packedG1MultiExpr) {
//      Stopwatch sw = Stopwatch.createStarted();
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
//        System.err.printf("\t\t%s %d multiExpr input parse\n", sw, i);
      }
      return new G1MultiInput(mulInputs);
    }
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

  record G2AddInput(byte[] g2a, byte[] g2b) {
    static G2AddInput unpadPair(byte[] packedG2Affine) {
      if (packedG2Affine.length != 512) {
        throw new RuntimeException(
            "BLST_ERROR: invalid input parameters, invalid input length for G2 Add");
      }
      byte[] g2a = new byte[192];
      System.arraycopy(packedG2Affine, 16, g2a, 0, 48);
      System.arraycopy(packedG2Affine, 80, g2a, 48, 48);
      System.arraycopy(packedG2Affine, 144, g2a, 0, 48);
      System.arraycopy(packedG2Affine, 208, g2a, 48, 48);
      byte[] g2b = new byte[192];
      System.arraycopy(packedG2Affine, 272, g2b, 0, 48);
      System.arraycopy(packedG2Affine, 336, g2b, 48, 48);
      System.arraycopy(packedG2Affine, 400, g2b, 0, 48);
      System.arraycopy(packedG2Affine, 464, g2b, 48, 48);
      return new G2AddInput(g2a, g2b);
    }
  }

  public record G2Output(byte[] padded) {
    static G2Output pad(byte[] unpadded) {
      if (unpadded.length != 192) {
        throw new RuntimeException("BLST_ERROR: invalid output parameter length for packed G2");
      }
      byte[] g2Out = new byte[256];
      System.arraycopy(unpadded, 0, g2Out, 16, 48);
      System.arraycopy(unpadded, 48, g2Out, 80, 48);
      System.arraycopy(unpadded, 96, g2Out, 144, 48);
      System.arraycopy(unpadded, 144, g2Out, 208, 48);
      return new G2Output(g2Out);
    }
  }

  public record G2Result(G2Output g2Out, Optional<String> optError) {
  }


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
   * @param packedG1Affines 256 byte array, comprising 2 G1 affines.  Points are 48 bytes, with each
   *                        left padded with 16 bytes, totaling 64 bytes per point.
   * @return g1Result
   */
  public static G1Result g1Mul(byte[] packedG1Affines) {
    // do not do subgroup checks on G1ADD according to EIP-2537 spec
    // get P1 points a and b from affine encoding as jacobian coords
    P1 p1;
    Scalar s;
    try {
      var g1MulInput = G1MulInput.unpad(packedG1Affines);
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
//      Stopwatch sw = Stopwatch.createStarted();
//      System.err.printf("\t%s starting multiExpr parse\n", sw);
      var g1MultiInput = G1MultiInput.unpad(packedG1MultiExpr);
//      System.err.printf("\t%s completed multiExpr parse\n", sw);

      var a = new P1_Affine(g1MultiInput.multiInputs[0].g1);
      if (!a.in_group()) {
        return new G1Result(null,
            Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
      }
      p1 = a.to_jacobian();
      s = g1MultiInput.multiInputs[0].s;

      // multiply
      P1 res = p1.mult(s);
//      System.err.printf("\t%s first multiExpr mul\n", sw);

      for (int i = 1; i < g1MultiInput.multiInputs.length; i++) {
        a = new P1_Affine(g1MultiInput.multiInputs[i].g1);
        if (!a.in_group()) {
          return new G1Result(null,
              Optional.of("BLST_ERROR: Point is not in the expected subgroup"));
        }
        p1 = a.to_jacobian();
        s = g1MultiInput.multiInputs[i].s;
//        System.err.printf("\t%s %d first multiExpr mul\n", sw, i);
        res = res.add(p1.mult(s));
//        System.err.printf("\t%s %d first multiExpr sum\n", sw, i);
      }

      // convert result to affine and return
      var g1Unpadded = res.to_affine().serialize();
//      System.err.printf("\t%s final multiExpr sum\n", sw);
      return new G1Result(G1Output.pad(g1Unpadded), Optional.empty());

    } catch (Exception ex) {
      return new G1Result(null, Optional.ofNullable(ex.getMessage()));
    }
  }

  /**
   * Add G2 points a and b, return the result.  Check that the result is on the curve, but do not do
   * subgroup checks per EIP-2537.
   *
   * @param packedG2Affines 256 byte array, comprising 2 G2 affines.  Points are 48 bytes, with each
   *                        left padded with 16 bytes, totaling 64 bytes per point.
   * @return g2Result
   */
  public static G2Result g2Add(byte[] packedG2Affines) {
    // do not do subgroup checks on G2ADD according to EIP-2537 spec
    // get P2 points a and b from affine encoding as jacobian coords
    P2 p2a, p2b;
    try {
      var g2AddInput = G2AddInput.unpadPair(packedG2Affines);
      p2a = new P2(new P2_Affine(g2AddInput.g2a));
      p2b = new P2(new P2_Affine(g2AddInput.g2b));
    } catch (Exception ex) {
      return new G2Result(null, Optional.of(ex.getMessage()));
    }

    // add
    P2 res = p2a.add(p2b);

    // convert result to affine and return
    var g2Unpadded = res.to_affine().serialize();
    return new G2Result(G2Output.pad(g2Unpadded), Optional.empty());
  }

}
