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

const plain = value => JSON.parse(JSON.stringify(value));

test('retains unknown inbound, client, transport, TLS certificate and sniffing fields', () => {
    const original = {
        protocol: 'vless', port: 8443, allocate: {strategy: 'always'},
        settings: {
            clients: [
                {id: 'first', flow: '', email: 'first@example.com', level: 2},
                {id: 'second', flow: '', email: 'second@example.com', level: 3},
            ],
            decryption: 'none', futureSetting: {enabled: true},
            fallbacks: [{dest: 8080, xver: 0, futureFallback: true}],
        },
        streamSettings: {
            network: 'xhttp', security: 'tls',
            sockopt: {tcpFastOpen: true, mark: 1},
            xhttpSettings: {
                host: 'cdn.example.com', path: '/old', mode: 'auto',
                headers: {'X-Ignored-By-Xray': 'old'},
                xPaddingBytes: '100-1000', noSSEHeader: true,
                extra: {scMaxEachPostBytes: 1000000, xmux: {maxConcurrency: '16-32'}, headers: {'X-Keep': 'yes', 'X-Remove': 'old'}},
            },
            tlsSettings: {
                serverName: 'example.com', minVersion: '1.3', rejectUnknownSni: true,
                certificates: [{certificateFile: '/cert', keyFile: '/key', usage: 'encipherment', oneTimeLoading: true}],
            },
        },
        sniffing: {enabled: true, destOverride: ['http', 'tls'], routeOnly: true, domainsExcluded: ['example.org']},
    };
    const restored = Inbound.fromJson(original);
    restored.settings.vlesses.reverse();
    restored.settings.vlesses.pop();
    restored.settings.vlesses[0].id = 'edited';
    restored.stream.xhttp.path = '/new';
    restored.stream.xhttp.headers.splice(1, 1);
    restored.sniffing.enabled = false;
    const result = plain(restored.toJson());
    assert.deepEqual(result.allocate, original.allocate);
    assert.deepEqual(result.settings.futureSetting, {enabled: true});
    assert.deepEqual(result.settings.clients, [{id: 'edited', flow: '', email: 'second@example.com', level: 3}]);
    assert.equal(result.settings.fallbacks[0].futureFallback, true);
    assert.deepEqual(result.streamSettings.sockopt, original.streamSettings.sockopt);
    assert.equal(result.streamSettings.xhttpSettings.path, '/new');
    assert.equal(result.streamSettings.xhttpSettings.headers, undefined);
    assert.deepEqual(result.streamSettings.xhttpSettings.extra.headers, {'X-Keep': 'yes'});
    assert.equal(result.streamSettings.xhttpSettings.xPaddingBytes, '100-1000');
    assert.deepEqual(result.streamSettings.xhttpSettings.extra, {...original.streamSettings.xhttpSettings.extra, headers: {'X-Keep': 'yes'}});
    assert.equal(result.streamSettings.tlsSettings.minVersion, '1.3');
    assert.equal(result.streamSettings.tlsSettings.rejectUnknownSni, true);
    assert.equal(result.streamSettings.tlsSettings.certificates[0].oneTimeLoading, true);
    assert.deepEqual(result.sniffing, {...original.sniffing, enabled: false});
    // The editor opens a copy through fromJson(toJson()); extra fields survive it too.
    assert.deepEqual(plain(Inbound.fromJson(result).toJson()), result);
    assert.equal(original.streamSettings.xhttpSettings.path, '/old');
});

test('preserves native raw/splithttp aliases and transport options using canonical forms', () => {
    const raw = StreamSettings.fromJson({
        network: 'raw', security: 'none',
        rawSettings: {acceptProxyProtocol: true, futureTransport: 1, header: {type: 'http', futureHeader: 'keep', request: {version: '1.0', path: ['/'], futureRequest: true}}},
    });
    let output = plain(raw.toJson());
    assert.equal(output.network, 'tcp');
    assert.equal(output.rawSettings, undefined);
    assert.equal(output.tcpSettings.futureTransport, 1);
    assert.equal(output.tcpSettings.header.futureHeader, 'keep');
    assert.equal(output.tcpSettings.header.request.version, '1.0');
    assert.equal(output.tcpSettings.header.request.futureRequest, true);
    raw.tcp.type = 'none';
    output = plain(raw.toJson());
    assert.equal(output.tcpSettings.header.request, undefined);

    const split = StreamSettings.fromJson({network: 'splithttp', splithttpSettings: {path: '/split', extra: {xPaddingBytes: '200-500'}}});
    output = plain(split.toJson());
    assert.equal(output.network, 'xhttp');
    assert.equal(output.splithttpSettings, undefined);
    assert.equal(output.xhttpSettings.path, '/split');
    assert.equal(output.xhttpSettings.extra.xPaddingBytes, '200-500');

    for (const [network, key, unknown] of [
        ['ws', 'wsSettings', {host: 'ws.example.com', heartbeatPeriod: 30}],
        ['grpc', 'grpcSettings', {idle_timeout: 60}],
        ['httpupgrade', 'httpupgradeSettings', {futureOption: {keep: true}}],
        ['kcp', 'kcpSettings', {seed: 'keep-seed', header: {type: 'none'}}],
        ['hysteria', 'hysteriaSettings', {congestion: {type: 'bbr'}}],
        ['quic', 'quicSettings', {header: {type: 'none', futureHeader: true}}],
    ]) {
        output = plain(StreamSettings.fromJson({network, [key]: unknown}).toJson());
        for (const [field, value] of Object.entries(unknown)) assert.deepEqual(output[key][field], value, `${network}.${field}`);
    }
});

test('intentional protocol, network, security and certificate changes do not resurrect removed settings', () => {
    const inbound = Inbound.fromJson({
        protocol: 'vless', settings: {clients: [{id: 'old', email: 'old@example.com'}], decryption: 'none', futureOldProtocol: 1},
        streamSettings: {network: 'xhttp', security: 'tls', xhttpSettings: {extra: {xPaddingBytes: '100-1000'}}, tlsSettings: {minVersion: '1.3'}},
    });
    inbound.protocol = Protocols.VMESS;
    assert.equal(inbound.settings.toJson().futureOldProtocol, undefined);
    assert.equal(inbound.settings.toJson().clients[0].email, undefined);
    inbound.stream.network = 'ws';
    inbound.stream.security = 'none';
    let output = plain(inbound.toJson());
    assert.equal(output.streamSettings.xhttpSettings, undefined);
    assert.equal(output.streamSettings.tlsSettings, undefined);
    inbound.protocol = Protocols.TUN;
    assert.equal(plain(inbound.toJson()).streamSettings, undefined);

    const stream = StreamSettings.fromJson({network: 'tcp', security: 'tls', tlsSettings: {certificates: [{certificateFile: '/cert', keyFile: '/key', usage: 'encipherment'}]}});
    stream.tls.certs[0].useFile = false;
    stream.tls.certs[0].cert = 'inline-cert';
    stream.tls.certs[0].key = 'inline-key';
    output = plain(stream.toJson());
    assert.equal(output.tlsSettings.certificates[0].certificateFile, undefined);
    assert.equal(output.tlsSettings.certificates[0].keyFile, undefined);
    assert.deepEqual(output.tlsSettings.certificates[0].certificate, ['inline-cert']);
    assert.equal(output.tlsSettings.certificates[0].usage, 'encipherment');
});

test('retains unknown fields for every inbound settings model', () => {
    for (const protocol of Object.values(Protocols)) {
        const inbound = new Inbound(undefined, undefined, protocol);
        const source = plain(inbound.toJson());
        source.settings.futureProtocolOption = {enabled: true};
        const restored = Inbound.fromJson(source);
        assert.deepEqual(plain(restored.toJson()).settings.futureProtocolOption, {enabled: true}, protocol);
    }
});

test('XHTTP advanced JSON edits replace old options, reject invalid input and do not mutate prototypes', () => {
    const stream = StreamSettings.fromJson({network: 'xhttp', xhttpSettings: {extra: {xPaddingBytes: '100-1000'}, noSSEHeader: true}});
    stream.xhttp.advancedJSON = '{"extra":{"scMaxEachPostBytes":2000000}}';
    let output = plain(stream.toJson()).xhttpSettings;
    assert.deepEqual(output.extra, {scMaxEachPostBytes: 2000000});
    assert.equal(output.noSSEHeader, undefined);
    stream.xhttp.advancedJSON = '{}';
    assert.equal(plain(stream.toJson()).xhttpSettings.extra, undefined);
    for (const value of ['{', '[]', 'null', '123', '{"host":"duplicate"}', '{"extra":[]}', '{"extra":{"headers":{"X-Duplicate":"value"}}}']) {
        stream.xhttp.advancedJSON = value;
        assert.notEqual(stream.xhttp.advancedError, '', value);
        assert.throws(() => stream.toJson(), /XHTTP|上方表单/, value);
    }
    stream.xhttp.advancedJSON = '{"__proto__":{"polluted":true},"extra":{"constructor":{"prototype":{"polluted":true}}}}';
    output = plain(stream.toJson()).xhttpSettings;
    assert.equal(Object.prototype.polluted, undefined);
    assert.equal(output.extra.constructor.prototype.polluted, true);
    assert.equal(Object.prototype.hasOwnProperty.call(output, '__proto__'), true);
    stream.xhttp.advancedJSON = ' ';
    assert.equal(stream.xhttp.advancedError, '');
    assert.equal(plain(stream.toJson()).xhttpSettings.extra, undefined);
});

test('XHTTP headers follow the effective extra location when advanced options are toggled', () => {
    const stream = StreamSettings.fromJson({network: 'xhttp', xhttpSettings: {headers: {'X-Active': 'root'}}});
    stream.xhttp.advancedJSON = '{"extra":{"xPaddingBytes":"100-1000"}}';
    let output = plain(stream.toJson()).xhttpSettings;
    assert.equal(output.headers, undefined);
    assert.deepEqual(output.extra.headers, {'X-Active': 'root'});
    stream.xhttp.headers[0].value = 'edited';
    stream.xhttp.advancedJSON = '{}';
    output = plain(stream.toJson()).xhttpSettings;
    assert.equal(output.extra, undefined);
    assert.deepEqual(output.headers, {'X-Active': 'edited'});
    const legacyNull = StreamSettings.fromJson({network: 'xhttp', xhttpSettings: {extra: null}});
    assert.deepEqual(plain(legacyNull.toJson()).xhttpSettings.extra, {});
});

test('preserves CA certificate files without private keys and arbitrary header names safely', () => {
    const stream = StreamSettings.fromJson({
        network: 'ws', security: 'tls',
        tlsSettings: {certificates: [{certificateFile: '/ca.pem', usage: 'verify'}]},
        wsSettings: {headers: JSON.parse('{"__proto__":"value","constructor":"keep"}')},
    });
    const output = plain(stream.toJson());
    assert.equal(output.tlsSettings.certificates[0].certificateFile, '/ca.pem');
    assert.equal(output.tlsSettings.certificates[0].usage, 'verify');
    assert.equal(output.wsSettings.headers.__proto__, 'value');
    assert.equal(output.wsSettings.headers.constructor, 'keep');
    assert.equal(Object.prototype.polluted, undefined);
});

test('unknown fields survive Vue observation and XHTTP validation reacts to edits', () => {
    const Vue = require(`${root}/web/assets/vue@2.7.16/vue.min.js`);
    const inbound = Inbound.fromJson({
        protocol: 'vless', settings: {clients: [{id: 'test', email: 'keep@example.com'}], decryption: 'none'},
        streamSettings: {network: 'xhttp', sockopt: {tcpFastOpen: true}, xhttpSettings: {extra: {xPaddingBytes: '100-1000'}}},
    });
    const app = new Vue({
        data: {inbound},
        computed: {validationError() { return this.inbound.stream.xhttp.advancedError; }},
    });
    assert.equal(app.validationError, '');
    app.inbound.stream.xhttp.advancedJSON = '{invalid';
    assert.notEqual(app.validationError, '');
    app.inbound.stream.xhttp.advancedJSON = '{}';
    assert.equal(app.validationError, '');
    const output = plain(app.inbound.toJson());
    assert.equal(output.settings.clients[0].email, 'keep@example.com');
    assert.equal(output.streamSettings.sockopt.tcpFastOpen, true);
    assert.equal(output.streamSettings.xhttpSettings.extra, undefined);
    app.$destroy();
});

test('inbound modal blocks submission when XHTTP JSON is invalid', () => {
    let submitted = false;
    const template = fs.readFileSync(`${root}/web/html/xui/inbound_modal.html`, 'utf8');
    vm.runInContext(`
        class DBInbound {}
        class Vue { constructor() {} }
        ${template.match(/<script>([\s\S]*?)<\/script>/)[1]}
        globalThis.testModal = inModal;
    `, context);
    const modal = context.testModal;
    modal.confirm = () => { submitted = true; };
    modal.inbound.stream.network = 'xhttp';
    modal.inbound.stream.xhttp.advancedJSON = '{broken';
    modal.ok();
    assert.equal(submitted, false);
    assert.notEqual(modal.validationError, '');
    modal.inbound.stream.xhttp.advancedJSON = '{}';
    modal.ok();
    assert.equal(submitted, true);
});
