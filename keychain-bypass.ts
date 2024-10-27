import { type Decodable, Decoder } from "@ndn/tlv";
import { execa } from "execa";
import { SafeBag } from "@ndn/ndnsec";

export async function invokeNdnsec(argv: string[], input?: Uint8Array): Promise<{
 readonly lines: string[];
 decode: <R>(d: Decodable<R>) => R;
}> {
 const { stdout } = await execa("ndnsec", argv, {
  input: input && btoa(Array.from(input, (x) => String.fromCodePoint(x)).join()),
  stderr: "inherit",
 });
 return {
  get lines() {
   return stdout.split("\n");
  },
  decode<R>(d: Decodable<R>): R {
   const wireStr = atob(stdout);
   const wire = Uint8Array.from(wireStr, (m) => m.codePointAt(0) || 0);
   return Decoder.decode(wire, d);
  },
 };
}

export async function getSafeBag(certNameStr: string, passphrase: string): Promise<SafeBag> {
 const exported = await invokeNdnsec(["export", "-c", certNameStr, "-P", passphrase]);
 return exported.decode(SafeBag);
} 