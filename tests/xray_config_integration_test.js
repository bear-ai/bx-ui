const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');

const binary = process.env.XRAY_TEST_BINARY;

function loadModel() {
    const root = process.cwd();
    const source = [
        fs.readFileSync(`${root}/web/assets/js/util/utils.js`, 'utf8'),
        fs.readFileSync(`${root}/web/assets/js/model/xray.js`, 'utf8'),
        'globalThis.model = { Protocols, VmessMethods, SSMethods, Inbound };',
    ].join('\n');
    const context = vm.createContext({
        console,
        URL,
        URLSearchParams,
        Uint8Array,
        safeBase64: value => Buffer.from(value).toString('base64url'),
        base64: value => Buffer.from(value).toString('base64'),
    });
    vm.runInContext(source, context);
    return context.model;
}

function runXray(args, input='') {
    const result = spawnSync(binary, args, {input, encoding: 'utf8'});
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    return result.stdout;
}

function checkInbound(name, inbound, allowInterfacePermissionError=false) {
    const inboundConfig = JSON.parse(JSON.stringify(inbound.toJson()));
    if (!inboundConfig.listen) delete inboundConfig.listen;
    const config = {
        inbounds: [inboundConfig],
        outbounds: [{protocol: 'freedom'}],
    };
    const result = spawnSync(binary, ['run', '-test', '-c', 'stdin:'], {
        input: JSON.stringify(config),
        encoding: 'utf8',
    });
    if (allowInterfacePermissionError && result.status !== 0) {
        assert.match(`${result.stdout}\n${result.stderr}`, /operation not permitted|permission denied/i);
        return;
    }
    assert.equal(result.status, 0, `${name}:\n${result.stdout}\n${result.stderr}`);
    assert.match(`${result.stdout}\n${result.stderr}`, /Configuration OK/);
}

test('generated inbound configurations load in current Xray', {skip: !binary}, () => {
    const { Protocols, VmessMethods, SSMethods, Inbound } = loadModel();
    const x25519 = runXray(['x25519']);
    const privateKey = /^PrivateKey:\s*(.+)$/m.exec(x25519)[1].trim();
    const publicKey = /^(?:Password \(PublicKey\)|PublicKey):\s*(.+)$/m.exec(x25519)[1].trim();

    for (const method of Object.values(VmessMethods)) {
        const inbound = new Inbound(undefined, undefined, Protocols.VMESS);
        inbound.settings.vmesses[0].security = method;
        checkInbound(`vmess/${method}`, inbound);
    }

    for (const method of Object.values(SSMethods)) {
        const inbound = new Inbound(undefined, undefined, Protocols.SHADOWSOCKS);
        inbound.settings.method = method;
        inbound.settings.password = contextSafePassword(method, inbound);
        checkInbound(`shadowsocks/${method}`, inbound);
    }

    for (const network of ['tcp', 'kcp', 'ws', 'grpc', 'httpupgrade', 'xhttp']) {
        const inbound = new Inbound(undefined, undefined, Protocols.VLESS);
        inbound.stream.network = network;
        checkInbound(`vless/${network}`, inbound);
    }

    const encOutput = runXray(['vlessenc']);
    const baseDecryptions = Array.from(encOutput.matchAll(/^\s*"decryption":\s*"([^"]+)"/gm), match => match[1]);
    const baseEncryptions = Array.from(encOutput.matchAll(/^\s*"encryption":\s*"([^"]+)"/gm), match => match[1]);
    for (let i = 0; i < baseDecryptions.length; ++i) {
        for (const mode of ['native', 'xorpub', 'random']) {
            const encrypted = new Inbound(undefined, undefined, Protocols.VLESS);
            encrypted.settings.decryption = baseDecryptions[i].replace('.native.', `.${mode}.`);
            encrypted.settings.encryption = baseEncryptions[i].replace('.native.', `.${mode}.`);
            checkInbound(`vless/encryption/${i}/${mode}`, encrypted);
        }
    }

    const reality = new Inbound(undefined, undefined, Protocols.VLESS);
    reality.stream.security = 'reality';
    reality.stream.reality.privateKey = privateKey;
    reality.stream.reality.publicKey = publicKey;
    reality.stream.reality.shortIds = ['12ab'];
    checkInbound('vless/reality', reality);

    for (const protocol of [Protocols.TROJAN, Protocols.SOCKS, Protocols.MIXED, Protocols.HTTP]) {
        checkInbound(protocol, new Inbound(undefined, undefined, protocol));
    }

    for (const protocol of [Protocols.DOKODEMO, Protocols.TUNNEL]) {
        const inbound = new Inbound(undefined, undefined, protocol);
        inbound.settings.address = '127.0.0.1';
        inbound.settings.port = 8080;
        checkInbound(protocol, inbound);
    }

    const wireguard = new Inbound(undefined, undefined, Protocols.WIREGUARD);
    wireguard.settings.secretKey = privateKey;
    wireguard.settings.addPeer();
    wireguard.settings.peers[0].publicKey = publicKey;
    checkInbound('wireguard', wireguard);

    const hysteria = new Inbound();
    hysteria.protocol = Protocols.HYSTERIA;
    hysteria.stream.tls.certs = [];
    checkInbound('hysteria', hysteria);

    const tun = new Inbound(undefined, undefined, Protocols.TUN);
    if (process.platform === 'darwin') tun.settings.name = 'utun9';
    checkInbound('tun', tun, true);
});

function contextSafePassword(method, inbound) {
    if (method === '2022-blake3-aes-128-gcm') {
        return Buffer.alloc(16, 1).toString('base64');
    }
    if (method.startsWith('2022-blake3-')) {
        return Buffer.alloc(32, 1).toString('base64');
    }
    return inbound.settings.password;
}
