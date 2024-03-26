import bodyParser from "body-parser";
import express from "express";
import {rsaEncrypt, symEncrypt, createRandomSymmetricKey, exportSymKey} from "../crypto";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import {Node} from "../registry/registry";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let prevMessageSent: any = null;
  let prevMessageReceived: any = null;
  let pathTemp : Node[] = [];

  // 1.2
  _user.get("/status", (req, res) => {
    res.send("live");
  });
  // 2.2
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: prevMessageReceived });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: prevMessageSent });
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: pathTemp.map((node) => node.nodeId) });
  });
  // 6.1
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;
    const nodes = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`)
        .then((res) => res.json())
        .then((body: any) => body.nodes);

    let path: Node[] = [];
    const shuffledNodes = nodes.sort(() => Math.random() - 0.5);
    path = shuffledNodes.slice(0, 3);

    let msg = message;
    if (!msg || msg.trim() === '') {
      res.status(400).json({ error: "The message can't be empty" });
      return;
    }
    let i = path.length - 1;
    while (i >= 0) {
      const node = path[i];
      const symKey = await createRandomSymmetricKey();
      const destination = i === path.length - 1 ?
          `${BASE_USER_PORT + destinationUserId}`.padStart(10, '0') :
          `${BASE_ONION_ROUTER_PORT + path[i + 1].nodeId}`.padStart(10, '0');
      const encryptedMSG = await symEncrypt(symKey, `${destination}${msg}`);
      const encryptedKey = await rsaEncrypt(await exportSymKey(symKey), node.pubKey);
      msg = encryptedKey + encryptedMSG;
      i--;
    }

    const currentNode = path[0];
    pathTemp = path
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + currentNode.nodeId}/message`, {
      method: "POST",
      body: JSON.stringify({ message: msg }),
      headers: {
        "Content-Type": "application/json",
      },
    });
    prevMessageSent = message;
    res.send("success");
  });
  // 6.2
  _user.post("/message", (req, res) => {
    prevMessageReceived = req.body.message;
    if (prevMessageReceived) {
      res.status(200).send("success");
    } else {
      res.status(400).json({ error: 'message must not be empty' });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
        `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}