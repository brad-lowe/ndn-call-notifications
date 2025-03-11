import { load as loadDotenv } from 'https://deno.land/std@0.214.0/dotenv/mod.ts';
import { sleep } from 'https://deno.land/x/sleep@v1.3.0/mod.ts';
import { InMemoryStorage } from '@ucla-irl/ndnts-aux/storage';
import { Workspace } from '@ucla-irl/ndnts-aux/workspace';
import { AsyncDisposableStack, base64ToBytes } from '@ucla-irl/ndnts-aux/utils';
import { CertStorage } from '@ucla-irl/ndnts-aux/security';
import { Decoder } from '@ndn/tlv';
import { Component, Data, Name, ValidityPeriod } from '@ndn/packet';
import { Certificate, CertNaming, createSigner, createVerifier, ECDSA } from '@ndn/keychain';
import { WsTransport } from '@ndn/ws-transport';
import { UnixTransport } from '@ndn/node-transport';
import { digestSigning, Signer } from '@ndn/packet';
import * as nfdmgmt from '@ndn/nfdmgmt';
import { Forwarder, FwTracer } from '@ndn/fw';
import { fchQuery } from '@ndn/autoconfig';
import * as Y from 'yjs';
import { produce } from '@ndn/endpoint';
import { fromHex } from '@ndn/util';
import { syncedStore, getYjsDoc } from '@syncedstore/core'
import * as fs from 'fs'
import * as nodemailer from 'nodemailer'
import { yXmlFragmentToProsemirrorJSON, yXmlFragmentToProseMirrorRootNode } from 'y-prosemirror'
import { DOMSerializer, Node } from "prosemirror-model";
import { JSDOM } from 'jsdom'
import { mySchema } from './my-schema.ts';


// Global configurations
let DEBUG = false;
// const UPDATE_INTERVAL = [300, 1000];
const UPDATE_INTERVAL = [10, 11];
const MAX_SEQUENCE = 1000;
const PAYLOAD_LENGTH = 100;
const LOCAL = false; // set to true if you want to use local NFD and use get_info_local

const groupKeyBits = fromHex('0102030405060708090A0B0C0D0E0F10');

const decodeCert = (b64Value: string) => {
  const wire = base64ToBytes(b64Value);
  const data = Decoder.decode(wire, Data);
  const cert = Certificate.fromData(data);
  return cert;
};

const payloadValue = Array.from({ length: PAYLOAD_LENGTH }).map(() => 'a').join('');

const decodeKeys = async (
  tag: string,
  certB64?: string,
  prvB64?: string,
): Promise<[Signer, Certificate]> => {
  if (!certB64 || !prvB64) {
    throw new Error(`${tag} key is missing`);
  }
  const cert = decodeCert(certB64);
  console.log(`${tag} Cert: ${cert.name.toString()} \n  Period: ${cert.validity.toString()}`);
  const prvKeyBits = base64ToBytes(prvB64);
  const keyPair = await ECDSA.cryptoGenerate({
    importPkcs8: [prvKeyBits, cert.publicKeySpki],
  }, true);
  const signer = createSigner(
    cert.name.getPrefix(cert.name.length - 2),
    ECDSA,
    keyPair,
  ).withKeyLocator(cert.name);
  return [signer, cert];
};

const randomUint = () => crypto.getRandomValues(new Uint32Array(1))[0];

const issue = async (idName: Name, issuerPrivateKey: Signer): Promise<[Signer, Certificate, ArrayBuffer]> => {
  const keyName = CertNaming.makeKeyName(idName);
  const algo = ECDSA;
  const gen = await ECDSA.cryptoGenerate({}, true);
  const privateKey = createSigner(keyName, algo, gen);
  const publicKey = createVerifier(keyName, algo, gen);
  const prvKeyBits = await crypto.subtle.exportKey('pkcs8', gen.privateKey);
  const cert = await Certificate.issue({
    validity: ValidityPeriod.daysFromNow(1),
    issuerId: new Component(8, 'CA'),
    issuerPrivateKey,
    publicKey,
  });
  return [privateKey, cert, prvKeyBits];
};

const doFch = async () => {
  try {
    const fchRes = await fchQuery({
      transport: 'wss',
      // transport: 'tcp', // Cannot use TCP/UDP due to prefix registration failure
      network: 'ndn',
    });

    if (fchRes.routers.length > 0) {
      return new URL(fchRes.routers[0].connect).host;
    } else {
      console.error('FCH gives no response.');
      Deno.exit(1);
    }
  } catch {
    console.error('FCH server is down');
    Deno.exit(1);
  }
};

const registerPrefixes = async (fw: Forwarder, workspaceName: Name, nodeId: Name, signer: Signer) => {
  // Register prefixes
  const cr = await nfdmgmt.invoke('rib/register', {
    name: workspaceName,
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    cOpts: { fw },
    prefix: LOCAL ? nfdmgmt.localhostPrefix : nfdmgmt.localhopPrefix,
    signer: LOCAL ? digestSigning : signer,
  });
  if (cr.statusCode !== 200) {
    console.error(
      `[${Deno.env.get('NODE_ID')}:${Deno.env.get('HOST')}]Unable to register route: ${cr.statusCode} ${cr.statusText}`,
    );
    Deno.exit();
  }
  const cr2 = await nfdmgmt.invoke('rib/register', {
    name: nodeId,
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    cOpts: { fw },
    prefix: LOCAL ? nfdmgmt.localhostPrefix : nfdmgmt.localhopPrefix,
    signer: LOCAL ? digestSigning : signer,
  });
  if (cr2.statusCode !== 200) {
    console.error(
      `[${Deno.env.get('NODE_ID')}:${
        Deno.env.get('HOST')
      }]Unable to register route: ${cr2.statusCode} ${cr2.statusText}`,
    );
    Deno.exit();
  }
};

const main = async () => {
  const testbedCertB64 = Deno.env.get('TESTBED_CERT');
  const testbedPrvKeyB64 = Deno.env.get('TESTBED_PRVKEY');
  const caCertB64 = Deno.env.get('WORKSPACE_CA_CERT');
  const caPrvKeyB64 = Deno.env.get('WORKSPACE_CA_PRVKEY');
  const nodeIdInt = parseInt(Deno.env.get('NODE_ID') ?? '0');
  // const host = Deno.env.get('HOST') ?? '';

  await using closers = new AsyncDisposableStack();

  // Load credentials
  const [testbedSigner, testbedCert] = await decodeKeys('Testbed', testbedCertB64, testbedPrvKeyB64);
  const [caSigner, caCert] = await decodeKeys('Workspace CA', caCertB64, caPrvKeyB64);
  const workspaceName = caCert.name.getPrefix(caCert.name.length - 4);

  // Generate node identity
  const nodeIdStr = `node-${nodeIdInt}-${randomUint()}`;
  const nodeId = workspaceName.append(nodeIdStr);
  const [_mySigner, myCert, myKeyBits] = await issue(nodeId, caSigner);
  console.log(`[${nodeIdInt}]My Cert: ${myCert.name.toString()} \n  Period: ${myCert.validity.toString()}`);
  // console.log(`[${nodeIdInt}]DEST: ${host}`);

  // Connect to testbed
  const fw = Forwarder.getDefault();
  const host = await doFch();
  // const wsUrl = `wss://${host}/ws/`;
  // const wsFace = await WsTransport.createFace({ l3: { local: false }, fw }, wsUrl);
  let face;
  try {
    if (LOCAL) {
      face = await UnixTransport.createFace({ l3: { local: true }, fw }, '/var/run/nfd/nfd.sock');
      console.log("local")
    } else {
      const wsUrl = `wss://${host}/ws/`;
      console.log("URL")
      console.log(wsUrl);
      face = await WsTransport.createFace({ l3: { local: false }, fw }, wsUrl);
      // face = await TcpTransport.createFace({ l3: { local: false }, fw }, { host, port: 6363 });
      // face = await UdpTransport.createFace({ l3: { local: false }, fw }, { host });
    }
  } catch (err) {
    console.error(`[${nodeIdInt}]Unable to connect: ${host}: ${err}`);
    return;
  }
  closers.defer(() => face.close());

  // Create workspace
  const storage = new InMemoryStorage();
  closers.use(storage);
  const certStore = new CertStorage(caCert, myCert, storage, fw, new Uint8Array(myKeyBits));

  // Serve certificate
  const certProducer = produce(
    testbedCert.name.getPrefix(testbedCert.name.length - 2),
    () => Promise.resolve(testbedCert.data),
  );
  closers.defer(() => certProducer.close());

  // Register prefixes
  try {
    await registerPrefixes(fw, workspaceName, nodeId, testbedSigner);
  } catch (err) {
    console.error(`[${nodeIdInt}]Unable to register: ${err}`);
    // await sleep(180);
    return;
  }

  function initRootDoc(guid: string) {
    return syncedStore(
      {
        latex: {},
        chats: [],
      },
      new Y.Doc({ guid }),
    )
  }

  let yDoc = new Y.Doc();

  // Run workspace
  let rootDoc = initRootDoc("00000000-0000-0000-0000-000000000001");
  console.log(rootDoc);

  yDoc = getYjsDoc(rootDoc);

  const createNewDoc: (() => Promise<void>) | undefined = async () => {
    if (!rootDoc) return

    yDoc = getYjsDoc(rootDoc);
    const clientID = yDoc.clientID;
    yDoc.clientID = 1;
    rootDoc.latex["00000000-0000-0000-0000-000000000000"] = {
      id: "00000000-0000-0000-0000-000000000000",
      name: '',
      parentId: undefined,
      kind: 'folder',
      items: [],
    };
    yDoc.clientID = clientID;
  }

  const workspace = await Workspace.create({
    nodeId: nodeId,
    persistStore: storage,
    fw: fw,
    rootDoc: getYjsDoc(rootDoc),
    signer: certStore.signer,
    verifier: certStore.verifier,
    createNewDoc: createNewDoc,
    useBundler: true,
  })

  closers.defer(() => workspace.destroy());
  console.log(`[${nodeIdInt}]Workspace started.`);

  await sleep(5);

  // Get underlying text from the yDoc
  const yMap = yDoc.getMap('latex')
  let file_id = ""
  yMap.forEach((value, id) => {
    if (value.get("name") == "Issues.md") {
      file_id = id
    }
  })
  console.log(file_id)
  let file = yMap.get(file_id)
  // // NOTE:If you want to choose by id, uncomment these lines:
  // file = yMap.get("802813a1-477f-46aa-a89e-5f580b4e4e23")
  // console.log(file)


  const fragment = file.get('prosemirror')
  const json = yXmlFragmentToProsemirrorJSON(fragment)
  console.log(json)

  let dom = new JSDOM('<!DOCTYPE html><div id="content"></div>')
  let document = dom.window.document

  let target = document.querySelector("div")

  let contentNode = Node.fromJSON(mySchema, json)

  DOMSerializer
  .fromSchema(mySchema)
  .serializeFragment(contentNode.content, {
    "document": document
  }, target)

  let html = document.getElementById("content").innerHTML
  console.log(html)

  // Read email sample and insert issues

  let email = fs.readFileSync('./mail-template.html', 'utf-8');

  const hr1 = email.indexOf("<hr>") + 4
  const hr2 = email.indexOf("<hr>", hr1)

  email = email.substring(0, hr1) + html + email.substring(hr2)

  console.log(email)

  // Send email via nodemailer

  var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: Deno.env.get('EMAIL_SENDER'),
      pass: Deno.env.get('EMAIL_SENDER_PASS')
    }
  });

  var mailOptions = {
    from: Deno.env.get('EMAIL_SENDER'),
    to: Deno.env.get('EMAIL_RECEIVER'),
    subject: 'NDN Weekly Call',
    html: email
  };

  transporter.sendMail(mailOptions, function(error, info){
    if (error) {
      console.log(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });


  // Exit signal
  let stop = false;
  const { promise: exitSignal, resolve: exitResolve } = Promise.withResolvers<void>();
  Deno.addSignalListener('SIGINT', () => {
    console.log(`[${nodeIdInt}]Stopped by Ctrl+C`);
    stop = true;
    exitResolve();
  });

  // Await close

  if (!stop) {
    const timer = setTimeout(() => {
      exitResolve(); // Assume all sequences are received at this time
    }, 15);
    await exitSignal;
    clearTimeout(timer);
  }

  console.log(`[${nodeIdInt}]Done`);
};

if (import.meta.main) {
  await loadDotenv({ export: true });
  DEBUG = Deno.env.get('DEBUG') ? true : false;
  if (DEBUG) FwTracer.enable();
  await main();
}
