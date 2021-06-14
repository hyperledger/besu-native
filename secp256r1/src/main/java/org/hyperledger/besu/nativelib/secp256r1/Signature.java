package org.hyperledger.besu.nativelib.secp256r1;

import java.util.Arrays;
import java.util.Objects;

public class Signature {
    private final byte[] r;
    private final byte[] s;
    private final byte v;

    public Signature(byte[] r, byte[] s, byte v) {
        this.r = r;
        this.s = s;
        this.v = v;
    }

    public byte[] getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }

    public byte getV() {
        return v;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Signature signature = (Signature) o;
        return v == signature.v && Arrays.equals(r, signature.r) && Arrays.equals(s, signature.s);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(v);
        result = 31 * result + Arrays.hashCode(r);
        result = 31 * result + Arrays.hashCode(s);
        return result;
    }

    @Override
    public String toString() {
        return "Signature{" +
                "r=" + Arrays.toString(r) +
                ", s=" + Arrays.toString(s) +
                ", v=" + v +
                '}';
    }
}
