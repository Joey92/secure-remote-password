import * as params from "./lib/params";
import { modPow, randomBigInt } from "./lib/util";

export interface Ephemeral {
  public: bigint;
  secret: bigint;
}

export interface Session {
  key: bigint;
  proof: bigint;
}

export function generateEphemeral(verifier: bigint): Ephemeral {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  const { N, g, k } = params;

  // v    Password verifier
  const v = verifier;

  // B = kv + g^b             (b = random number)
  const b = randomBigInt(params.hashOutputBytes);
  const B = k * v + (modPow(g, b, N) % N);

  return {
    secret: b,
    public: B,
  };
}

export function deriveSession(
  serverSecretEphemeral: bigint,
  clientPublicEphemeral: bigint,
  salt: bigint,
  username: string,
  verifier: bigint,
  clientSessionProof: bigint
): Session {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()  One-way hash function
  const { N, g, k, H } = params;

  // b    Secret ephemeral values
  // A    Public ephemeral values
  // s    User's salt
  // p    Cleartext Password
  // I    Username
  // v    Password verifier
  const b = serverSecretEphemeral;
  const A = clientPublicEphemeral;
  const s = salt;
  const I = String(username);
  const v = verifier;

  // B = kv + g^b             (b = random number)
  const B = k * v + (modPow(g, b, N) % N);

  // A % N > 0
  if (A % N == 0n) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The client sent an invalid public ephemeral");
  }

  // u = H(A, B)
  const u = H(A, B);

  // S = (Av^u) ^ b              (computes session key)
  const S = modPow(A * modPow(v, u, N), b, N);

  // K = H(S)
  const K = H(S);

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = H(H(N) ^ H(g), H(I), s, A, B, K);

  const expected = M;
  const actual = BigInt(clientSessionProof);

  if (actual != expected) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Client provided session proof is invalid");
  }

  // P = H(A, M, K)
  const P = H(A, M, K);

  return {
    key: K,
    proof: P,
  };
}
