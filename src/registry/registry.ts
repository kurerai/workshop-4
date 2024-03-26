import bodyParser from "body-parser";
import express from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const nodesRegistry: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  const registeredNodes: GetNodeRegistryBody = { nodes: [] };

  _registry.post("/registerNode", (req, res) => {
    try {
      const { nodeId, pubKey } = req.body;

      const nodeIdExists = registeredNodes.nodes.some(node => node.nodeId === nodeId);
      if (nodeIdExists) {
        return res.json({ success: false, error: 'Node ID already exists' });
      }

      const isValidPubKey = /^[a-zA-Z0-9+/]+={0,2}$/.test(pubKey);
      if (!isValidPubKey) {
        return res.json({ success: false, error: 'Invalid public key format' });
      }

      const pubKeyExists = registeredNodes.nodes.some(node => node.pubKey === pubKey);
      if (pubKeyExists) {
        return res.json({ success: false, error: 'Public key already exists' });
      }

      const newNode: Node = { nodeId, pubKey };
      registeredNodes.nodes.push(newNode);
      return res.json({ success: true });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred while processing the request' });
    }
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    res.json(registeredNodes);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
