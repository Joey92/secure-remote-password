import srpclient from "./client";
import { defaults } from "./lib/params";
import srpserver from "./server";

describe("Secure Remote Password", () => {
  it("should authenticate a user", () => {
    const username = "linus@folkdatorn.se";
    const password = "$uper$ecure";

    const client = srpclient(defaults);
    const server = srpserver(defaults);

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
