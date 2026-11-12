import { buildPoseidon } from "circomlibjs";

let instance: any;

export async function initPoseidon() {
  if (!instance) instance = await buildPoseidon();
  return instance;
}

export function poseidonHash(inputs: bigint[]): bigint {
  if (!instance) throw new Error("call initPoseidon() first");
  return instance.F.toObject(instance(inputs));
}