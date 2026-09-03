const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const root = process.cwd();
const source = [
    fs.readFileSync(`${root}/web/assets/js/util/utils.js`, 'utf8'),
    fs.readFileSync(`${root}/web/assets/js/model/xray.js`, 'utf8'),
    'globalThis.model = { Protocols, VmessMethods, SSMethods, FLOW_CONTROL, StreamSettings, Inbound };',
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

const { Protocols, VmessMethods, SSMethods, FLOW_CONTROL, StreamSettings, Inbound } = context.model;

test('exposes every inbound protocol supported natively by current Xray', () => {
    const protocols = Object.values(Protocols);
    for (const protocol of [
        'vmess', 'vless', 'trojan', 'shadowsocks', 'dokodemo-door', 'tunnel',
        'socks', 'mixed', 'http', 'wireguard', 'hysteria', 'tun',
    ]) {
        assert.ok(protocols.includes(protocol), protocol);
    }
});

test('contains current VMess and Shadowsocks ciphers', () => {
    assert.deepEqual(
        Array.from(Object.values(VmessMethods)),
        ['aes-128-gcm', 'chacha20-poly1305', 'auto', 'none', 'zero'],
    );
    for (const method of [
        'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305',
        'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
        '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
        '2022-blake3-chacha20-poly1305',
    ]) {
        assert.ok(Object.values(SSMethods).includes(method), method);
    }
});

test('generates correctly-sized Shadowsocks 2022 PSKs', () => {
    for (const [method, size] of [
        [SSMethods.BLAKE3_AES_128_GCM, 16],
        [SSMethods.BLAKE3_AES_256_GCM, 32],
        [SSMethods.BLAKE3_CHACHA20_POLY1305, 32],
    ]) {
        const settings = new Inbound.ShadowsocksSettings(Protocols.SHADOWSOCKS, method);
        assert.equal(Buffer.from(settings.password, 'base64').length, size);
    }
});

test('round-trips VMess security and VLESS encryption metadata', () => {
    const vmess = new Inbound(undefined, undefined, Protocols.VMESS);
    vmess.settings.vmesses[0].security = VmessMethods.ZERO;
    assert.equal(Inbound.fromJson(vmess.toJson()).settings.vmesses[0].security, 'zero');

    const vless = new Inbound(undefined, undefined, Protocols.VLESS);
    vless.settings.decryption = 'server-key';
    vless.settings.encryption = 'client-key';
    const restored = Inbound.fromJson(vless.toJson());
    assert.equal(restored.settings.decryption, 'server-key');
    assert.equal(restored.settings.encryption, 'client-key');
    assert.equal(new URL(restored.genVLESSLink('example.com')).searchParams.get('encryption'), 'client-key');
});

test('round-trips modern transports and REALITY', () => {
    const stream = new StreamSettings();
    stream.network = 'xhttp';
    stream.xhttp.host = 'cdn.example.com';
    stream.xhttp.path = '/x';
    stream.xhttp.mode = 'stream-up';
    stream.security = 'reality';
    stream.reality.privateKey = 'private';
    stream.reality.publicKey = 'public';
    stream.reality.shortIds = ['12ab'];
    const restored = StreamSettings.fromJson(stream.toJson());
    assert.equal(restored.network, 'xhttp');
    assert.equal(restored.xhttp.mode, 'stream-up');
    assert.equal(restored.reality.publicKey, 'public');
    assert.deepEqual(Array.from(restored.reality.shortIds), ['12ab']);
});

test('new protocol models emit official Xray field names', () => {
    const tunnel = new Inbound(undefined, undefined, Protocols.TUNNEL);
    tunnel.settings.address = '127.0.0.1';
    tunnel.settings.port = 8080;
    tunnel.settings.addPortMap();
    tunnel.settings.portMaps[0].source = '80';
    tunnel.settings.portMaps[0].destination = '127.0.0.1:8080';
    assert.equal(tunnel.settings.toJson().portMap['80'], '127.0.0.1:8080');

    const tun = new Inbound(undefined, undefined, Protocols.TUN);
    assert.equal(tun.settings.toJson().MTU, 1500);

    const hysteria = new Inbound();
    hysteria.protocol = Protocols.HYSTERIA;
    assert.equal(hysteria.stream.network, 'hysteria');
    assert.equal(hysteria.stream.security, 'tls');
    assert.equal(hysteria.settings.toJson().version, 2);

    assert.equal(FLOW_CONTROL.VISION, 'xtls-rprx-vision');
});
