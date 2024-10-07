import { DenoKvStorage } from '@ucla-irl/ndnts-aux/storage';
import { Workspace } from '@ucla-irl/ndnts-aux/workspace';
import { AsyncDisposableStack, base64ToBytes } from '@ucla-irl/ndnts-aux/utils';
import { CertStorage } from '@ucla-irl/ndnts-aux/security';
import { Decoder } from '@ndn/tlv';
import { Data, digestSigning, Name } from '@ndn/packet';
import { Certificate } from '@ndn/keychain';
import { SafeBag } from '@ndn/ndnsec';
import { UnixTransport } from '@ndn/node-transport';
import * as nfdmgmt from '@ndn/nfdmgmt';
import { Forwarder, FwTracer } from '@ndn/fw';
import { sleep } from 'https://deno.land/x/sleep@v1.3.0/mod.ts';
import * as Y from 'yjs';

const TRUST_ANCHOR = `
Bv0BQwc3CBZuZmQtY2FsbC1ub3RpZmljYXRpb25zCANLRVkICONAeybKTnPeCARz
ZWxmNggAAAGQkO2FUBQJGAECGQQANu6AFVswWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARg6H+yejE8hyb93gky8NFqYWn7So6ZpyCHwbT6kYpYwJWjcVfKNDhuz+K5
IUDxtfIezoHvLDYKPPsmmcAWq6frFlgbAQMcKQcnCBZuZmQtY2FsbC1ub3RpZmlj
YXRpb25zCANLRVkICONAeybKTnPe/QD9Jv0A/g8yMDI0MDcwOFQwNjAwMDP9AP8P
MjA0NDA3MDNUMDYwMDAzF0YwRAIgR4dbUu7ivuAwsD1My0340KdxToOx6qQZ2vZY
XfemiqcCICARUj0z169MJYCwBg2wEfc6Jt4bndO5nRgSJDH/zSLl
`;

const SAFEBAG = `
gP0CQAb9AUMHNwgWbmZkLWNhbGwtbm90aWZpY2F0aW9ucwgDS0VZCAjjQHsmyk5z
3ggEc2VsZjYIAAABkJDthVAUCRgBAhkEADbugBVbMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEYOh/snoxPIcm/d4JMvDRamFp+0qOmacgh8G0+pGKWMCVo3FXyjQ4
bs/iuSFA8bXyHs6B7yw2Cjz7JpnAFqun6xZYGwEDHCkHJwgWbmZkLWNhbGwtbm90
aWZpY2F0aW9ucwgDS0VZCAjjQHsmyk5z3v0A/Sb9AP4PMjAyNDA3MDhUMDYwMDAz
/QD/DzIwNDQwNzAzVDA2MDAwMxdGMEQCIEeHW1Lu4r7gMLA9TMtN+NCncU6Dseqk
Gdr2WF33poqnAiAgEVI9M9evTCWAsAYNsBH3OibeG53TuZ0YEiQx/80i5YH3MIH0
MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCRRQ/K8eNhmqB9da5js4IL
AgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQcxUp6r8wOjkbMJkad0N9
VgSBkKzcVKwDwNZTyudI6Vod9oeQEvR3PCFKkDq562xvdFJ09lKpUJHthnk6apZz
2Id57RPgWblR0HmY4KfuVpfUZZlH+hKe6TL94E1dU3tiwBRtHsMOD8oHmaSKNuN5
oflBTrzEiUOx5L0h7bTB3olZSLZUrPBSAp9jR7hz9CkcNcrSo8YKgOKsfSdZGfvf
i0VrUg==
`;

const decodeCert = (b64Value: string) => {
  const wire = base64ToBytes(b64Value);
  const data = Decoder.decode(wire, Data);
  const cert = Certificate.fromData(data);
  return cert;
};

const decodeSafebag = async (b64Value: string, passcode: string) => {
  const wire = base64ToBytes(b64Value);
  const safebag = Decoder.decode(wire, SafeBag);
  const cert = safebag.certificate;
  const prvKey = await safebag.decryptKey(passcode);
  return { cert, prvKey };
};

const DEBUG = false;

const main = async () => {
  if (DEBUG) FwTracer.enable();

  await using closers = new AsyncDisposableStack();

  const trustAnchor = decodeCert(TRUST_ANCHOR);
  const { cert, prvKey } = await decodeSafebag(SAFEBAG, '123456');

  const fw = Forwarder.getDefault();
  const storage = await DenoKvStorage.create('./data/kv-store');
  closers.use(storage);
  const certStore = new CertStorage(trustAnchor, cert, storage, fw, prvKey);

  const face = await UnixTransport.createFace({ l3: { local: true } }, '/run/nfd/nfd.sock');
  closers.defer(() => face.close());
  // Not working. Registered wrong profixes (.../test/sync/alo)
  // enableNfdPrefixReg(face, {
  //   signer: digestSigning,
  // });
  // Register prefixes
  const cr = await nfdmgmt.invoke('rib/register', {
    name: new Name('/ndn-workspace/test'),
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    cOpts: { fw },
    prefix: nfdmgmt.localhostPrefix,
    signer: digestSigning,
  });
  if (cr.statusCode !== 200) {
    console.error(`Unable to register route: ${cr.statusCode} ${cr.statusText}`);
    Deno.exit();
  }
  const cr2 = await nfdmgmt.invoke('rib/register', {
    name: new Name('/ndn-workspace/test/node-2'),
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    cOpts: { fw },
    prefix: nfdmgmt.localhostPrefix,
    signer: digestSigning,
  });
  if (cr2.statusCode !== 200) {
    console.error(`Unable to register route: ${cr2.statusCode} ${cr2.statusText}`);
    Deno.exit();
  }

  // TODO: Run without a signer
  const workspace = await Workspace.create({
    nodeId: new Name('/ndn-workspace/test/node-2'),
    persistStore: storage,
    fw,
    rootDoc: new Y.Doc(),
    signer: certStore.signer,
    verifier: certStore.verifier,
  });
  closers.defer(() => workspace.destroy());

  const exitSignal = new Promise<void>((resolve) => {
    Deno.addSignalListener('SIGINT', () => {
      console.log('Stopped by Ctrl+C');
      resolve();
    });
  });
  await exitSignal;
};

if (import.meta.main) {
  await main();
}
