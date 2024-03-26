import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, importPrvKey, rsaDecrypt, symDecrypt } from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let prevMessageEncryptReceived: string | null = null;
  let prevMessageDecryptReceived: string | null = null;
  let prevDestination: number | null = null;
  const { publicKey, privateKey } = await generateRsaKeyPair();
  const pubKeyB64 = await exportPubKey(publicKey);
  const privKeyB64 = await exportPrvKey(privateKey);

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: prevMessageEncryptReceived });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: prevMessageDecryptReceived });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: prevDestination });
  });

  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privKeyB64 });
  });

  const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      nodeId: nodeId,
      pubKey: pubKeyB64,
    }),
  });

  if (!response.ok) {
    throw new Error("Node failed to register");
  }
  onionRouter.post("/message", async (req, res) => {
    const layer = req.body.message;
    if(!layer){
      res.status(400).json({ error: 'error with current layer' });
    }
    const encryptedKey = layer.slice(0, 344);
    const Key = privKeyB64 ? await rsaDecrypt(encryptedKey, await importPrvKey(privKeyB64)) : null;
    const msgEncrypted = layer.slice(344) as string;
    const msg = Key ? await symDecrypt(Key, msgEncrypted) : null;


    prevMessageDecryptReceived = msg ? msg.slice(10) : null;
    prevDestination = msg ? parseInt(msg.slice(0, 10), 10) : null;
    prevMessageEncryptReceived = layer;
    await fetch(`http://localhost:${prevDestination}/message`, {
      method: "POST",
      body: JSON.stringify({ message: prevMessageDecryptReceived }),
      headers: {
        "Content-Type": "application/json",
      },
    });

    res.send("success");
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
        `Onion router ${nodeId} is listening on port ${
            BASE_ONION_ROUTER_PORT + nodeId
        }`
    );
  });

  return server;
}