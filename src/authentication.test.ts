import * as client from "./client";
import * as server from "./server";

describe("Secure Remote Password", () => {
  it("should authenticate a user", () => {
    const username = "linus@folkdatorn.se";
    const password = "$uper$ecure";

    const salt = client.generateSalt();
    const privateKey = client.derivePrivateKey(salt, username, password);
    const verifier = client.deriveVerifier(privateKey);

    const clientEphemeral = client.generateEphemeral();
    const serverEphemeral = server.generateEphemeral(verifier);

    const clientSession = client.deriveSession(
      clientEphemeral.secret,
      serverEphemeral.public,
      salt,
      username,
      privateKey
    );
    const serverSession = server.deriveSession(
      serverEphemeral.secret,
      clientEphemeral.public,
      salt,
      username,
      verifier,
      clientSession.proof
    );

    client.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );

    expect(clientSession.key).toEqual(serverSession.key);
  });
});
