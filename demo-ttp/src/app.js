const {
    ConnectionsModule,
    DidsModule,
    V2ProofProtocol,
    V2CredentialProtocol,
    ProofsModule,
    AutoAcceptProof,
    AutoAcceptCredential,
    CredentialsModule,
    WsOutboundTransport,
    Agent,
    HttpOutboundTransport,
    KeyType, ConnectionEventTypes, DidExchangeState, TypedArrayEncoder, ProofEventTypes, ProofState, DidDocument,
    DifPresentationExchangeProofFormatService, JsonLdCredentialFormatService, JwaSignatureAlgorithm, DidDocumentBuilder,
    getEd25519VerificationKey2018, W3cCredentialsModule, CredentialEventTypes, SignatureSuiteRegistry,
    getEd25519VerificationKey2020, W3cJsonLdVerifiableCredential, CredentialState, W3cJsonLdVerifiablePresentation,
    JsonTransformer, W3cCredentialService, WebDidResolver, DidDocumentService, ConnectionService, DidCommV1Service,
    ConsoleLogger, LogLevel, RoutingService, HandshakeProtocol, MediationRecipientService, MediatorPickupStrategy,
    MediationRecipientModule, MediatorService, MediatorModule, OutOfBandEventTypes, PeerDidNumAlgo, ClaimFormat,
    CREDENTIALS_CONTEXT_V1_URL, WRAPPER_VP_CONTEXT_URL, W3cPresentationRequest, AgentMessage, Key, BasicMessage
} = require('@credo-ts/core')
const {
    AnonCredsCredentialFormatService,
    AnonCredsModule,
    AnonCredsProofFormatService,
    LegacyIndyCredentialFormatService,
    LegacyIndyProofFormatService,
    V1CredentialProtocol,
    V1ProofProtocol, DataIntegrityCredentialFormatService,
} = require('@credo-ts/anoncreds')
const QRCode = require('qrcode')
const {agentDependencies, HttpInboundTransport} = require('@credo-ts/node')
const {IndyVdrIndyDidResolver, IndyVdrAnonCredsRegistry, IndyVdrModule} = require('@credo-ts/indy-vdr')
const {indyVdr} = require('@hyperledger/indy-vdr-nodejs')
const {ariesAskar} = require('@hyperledger/aries-askar-nodejs')
const {AskarModule} = require('@credo-ts/askar')
const {anoncreds} = require('@hyperledger/anoncreds-nodejs')
const {AnonCredsRsModule} = require('@credo-ts/anoncreds')
const sys_config = require('config');
var bodyParser = require('body-parser');
const express = require('express');
const {randomUUID} = require("crypto");
const {EnvelopeService} = require("@credo-ts/core/build/agent/EnvelopeService");

const prompt = require('prompt-sync')();
const getGenesisTransaction = async (url) => {
    const response = await fetch(url)
    return await response.text()
}

let agent;
const initializeIssuerAgent = async (ledgerUrl, endPoint) => {

    const genesisTransactionsBCovrinTestNet = await getGenesisTransaction(ledgerUrl)

    const config = {
        label: sys_config.get('wallet.id'),
        walletConfig: {
            id: sys_config.get('wallet.id'),
            key: sys_config.get('wallet.key'),
        },
        endpoints: [endPoint],
        autoUpdateStorageOnStartup: true,
        logger: new ConsoleLogger(LogLevel.debug)
    }

    // A new instance of an agent is created here
    agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet),
    })

    // Register a simple `WebSocket` outbound transport - not needed
    //agent.registerOutboundTransport(new WsOutboundTransport())

    // Register a simple `Http` outbound transport
    agent.registerOutboundTransport(new HttpOutboundTransport())

    // Register a simple `Http` inbound transport
    agent.registerInboundTransport(new HttpInboundTransport({port: 3070}))

    // Initialize the agent
    await agent.initialize()


    let did = 'did:web:raw.githubusercontent.com:biagioboi:DKGNonRepudiation:main:demo-ttp:config'
    try {
        // Try to create the key for the wallet, if it already exists then jump these instructions
        const ed25519Key = await agent.wallet.createKey({
            keyType: KeyType.Ed25519,
            privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
        })

        const builder = new DidDocumentBuilder(did)
        const ed25519VerificationMethod2018 = getEd25519VerificationKey2018({
            key: ed25519Key,
            id: `${did}#${ed25519Key.fingerprint}`,
            controller: did,
        })

        builder.addService(new DidCommV1Service({
            "id": "#inline-0",
            "serviceEndpoint": sys_config.get('wallet.endpoint'),
            "type": "did-communication",
            "recipientKeys": [`${did}#${ed25519Key.fingerprint}`],
            "routingKeys": [`${did}#${ed25519Key.fingerprint}`]
        }));


        builder.addVerificationMethod(ed25519VerificationMethod2018)
        builder.addAuthentication(ed25519VerificationMethod2018.id)
        builder.addAssertionMethod(ed25519VerificationMethod2018.id)
        console.log(JSON.stringify(builder.build()));

        await agent.dids.create({
            method: 'web',
            didDocument: builder.build(),
            options: {
                keyType: KeyType.Ed25519,
                privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
            }
        })
    } catch (e) {
        let didResp = await agent.dids.resolve(did);
        let u = await agent.dids.resolveDidDocument(did)

        await agent.dids.import({
            did,
            didDocument: didResp.didDocument,
            overwrite: true,
            options: {
                keyType: KeyType.Ed25519,
                privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
            }
        })
        let created_dids = await agent.dids.getCreatedDids({method: 'web'});
        console.log("This is the TTP Wallet, it has this DID: " + created_dids[0].did);

    }


    return agent
}

async function startEverything() {
    agent = await initializeIssuerAgent(sys_config.get('wallet.ledger_url'), sys_config.get('wallet.endpoint'));
}

const app = express();
const PORT = 8082;
startEverything().then(result => {
    /* Empty */
})
const cors = require('cors');

app.use(cors());
app.use(express.static('public'))

app.use(express.json());
app.use(bodyParser.urlencoded({extended: false}));
app.get('/', (req, res) => {
    res.status(200);
    res.send("TTP Running.")
});

app.get('/generateInvitation', async (req, res) => {
    res.status(200);
    const outOfBandRecord = await agent.oob.createInvitation({
        autoAcceptConnection: true,
        handshake: true,
        invitationDid: "did:web:raw.githubusercontent.com:biagioboi:demo-ttp:main:config",
    })

    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({payload}) => {
        console.log(JSON.stringify(payload));
        if (payload.connectionRecord.state === DidExchangeState.Completed) {
            console.log(JSON.stringify(payload));
        }
    });
    console.log("I'm generating a new invitation");
    const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({domain: sys_config.get('wallet.endpoint')})
    res.json({url: invitationUrl, connectionId: outOfBandRecord.id})
});

app.post('/checkResource', async (req, res) => {
    res.status(200);
    console.log(req)
    let encMessage = req.body.encryptedMessage;
    if (!encMessage) {
        res.json({error: "Unable to process the request."})
        return;
    }


    let env_service = new EnvelopeService(new ConsoleLogger());
    let dec_message = await env_service.unpackMessage(agent.context, encMessage);
    const symKeyForDecrypt = dec_message.payloadKey;
    /* It is possible to unpack whatever we want, at this point it is better to obtain the key for the decrypt rather than decrypt the message */
    res.json({symKeyForDecrypt: symKeyForDecrypt})

})

app.listen(PORT, (error) => {
        if (!error)
            console.log("Server is Successfully Running, and App is listening on port " + PORT)
        else
            console.log("Error occurred, server can't start", error);
    }
);


function getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet) {
    const legacyIndyCredentialFormatService = new LegacyIndyCredentialFormatService()
    const legacyIndyProofFormatService = new LegacyIndyProofFormatService()
    /* Il problema della */
    return {
        connections: new ConnectionsModule({
            autoAcceptConnections: true,
            peerNumAlgoForDidRotation: PeerDidNumAlgo.GenesisDoc,
            peerNumAlgoForDidExchangeRequests: PeerDidNumAlgo.GenesisDoc
        }),
        credentials: new CredentialsModule({
            autoAcceptCredentials: AutoAcceptCredential.Never,
            credentialProtocols: [
                new V1CredentialProtocol({
                    indyCredentialFormat: legacyIndyCredentialFormatService,
                }),
                new V2CredentialProtocol({
                    credentialFormats: [legacyIndyCredentialFormatService, new AnonCredsCredentialFormatService(), new DataIntegrityCredentialFormatService(), new JsonLdCredentialFormatService()],
                }),
            ],
        }),
        proofs: new ProofsModule({
            autoAcceptProofs: AutoAcceptProof.ContentApproved,
            proofProtocols: [
                new V1ProofProtocol({
                    indyProofFormat: legacyIndyProofFormatService,
                }),
                new V2ProofProtocol({
                    proofFormats: [legacyIndyProofFormatService, new AnonCredsProofFormatService(), new DifPresentationExchangeProofFormatService()],
                }),
            ],
        }),
        anoncreds: new AnonCredsModule({
            registries: [new IndyVdrAnonCredsRegistry()],
        }),
        indyVdr: new IndyVdrModule({
            indyVdr,
            networks: [{
                // Need unique network id as we will have multiple agent processes in the agent
                id: randomUUID(),
                genesisTransactions: genesisTransactionsBCovrinTestNet,
                indyNamespace: 'bcovrin:test',
                isProduction: false,
                connectOnStartup: true,
            }],
        }),
        dids: new DidsModule({
            resolvers: [new IndyVdrIndyDidResolver(), new WebDidResolver()],
        }),
        askar: new AskarModule({
            ariesAskar,
        }),
        w3cCredentials: new W3cCredentialsModule(),
    }
}
