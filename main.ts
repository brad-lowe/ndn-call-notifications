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
Bv0BOQcxCANuZG4IC3dlZWtseS1jYWxsCANLRVkICKLXjAGJ/kLcCARzZWxmNggA
AAGSfkVHqhQJGAECGQQANu6AFVswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARw
QGjuS2M5L9CwTZ6xevhiMZ9fZnN64yoK3fOHfbR0FzMmbqz/wrh0gdRT14Ho7dz7
6vJz0Ux5u/B7KjEZWV3dFlIbAQMcIwchCANuZG4IC3dlZWtseS1jYWxsCANLRVkI
CKLXjAGJ/kLc/QD9Jv0A/g8yMDI0MTAxMlQwMTA4NDL9AP8PMjA0NDEwMDdUMDEw
ODQyF0gwRgIhAOzxzMcY58CYXmWVZbrDcoo1u0xoW7Mya3wlK09OxYymAiEA/xQq
u1UI7NZmxsCCHUhr8xn2gfMFi+bHHBTzjUy9ACU=
`;

const SAFEBAG = `
gP0CXAb9AV8HSAgDbmRuCAt3ZWVrbHktY2FsbAgJYnJhZC1sb3dlCANLRVkICChC
PlZ7sD/uCBAvbmRuL3dlZWtseS1jYWxsNggAAAGSfkeriRQJGAECGQQANu6AFVsw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASKmqCshGLfdrVwilvnPcwnmxekSNYJ
p1uZTliPKhU/4wCZ8sR+XEbysEpLdFnwCYp3/gVFsOJgZGFDphoOXP43FmIbAQMc
MwcxCANuZG4IC3dlZWtseS1jYWxsCANLRVkICKLXjAGJ/kLcCARzZWxmNggAAAGS
fkVHqv0A/Sb9AP4PMjAyNDEwMTJUMDExMTIw/QD/DzIwMjUxMDEyVDAxMTExORdH
MEUCIQD+KFNlhOqbCOd46sQHJh7agn+pSxYtBBRDYiTkB6VnKwIgYvaYRDS6lZnh
pvFPp1dTnhpjAMeYydeDHvv/qZG7E+OB9zCB9DBfBgkqhkiG9w0BBQ0wUjAxBgkq
hkiG9w0BBQwwJAQQvZzQaOVfcBg1Z++PGaBs3wICCAAwDAYIKoZIhvcNAgkFADAd
BglghkgBZQMEASoEEA4oHm/oh5767zQIsAYR8P4EgZD6iNpv9BPU07iW7ZDaksDD
9kpZJEH5lGEZrrAW2mRYmP+pss+dsc5hprT/Z8gTBCxOkSH3MjxYJ9P8JcqWa1N8
T3fakEgiW/vvvprpf5CqJ+jq8RxKQ48NtxqccCPdHGwdaUK0WWpijTPOOfjg1Rjt
4qZxZ0i3Qs6Lx5prtS0+VNa2SZRJhLKYV9lNuuKSt94=
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
