const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const installer = fs.readFileSync(path.join(root, 'install.sh'), 'utf8');
const manager = fs.readFileSync(path.join(root, 'x-ui.sh'), 'utf8');

function extract(source, name) {
    const body = source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'))?.[0];
    assert.ok(body, `script exposes ${name}`);
    return body;
}

// Run only extracted input/configuration functions, with a mocked binary.
// Never source either full script or touch the host's real application/services.
function runScript(t, mode, input, failures = {}) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bx-ui-password-install-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const program = path.join(directory, 'mock.js');
    const callsPath = path.join(directory, 'calls.jsonl');
    fs.writeFileSync(program, `
const fs = require('node:fs');
const args = process.argv.slice(2);
const password = args.includes('-password-stdin')
    ? fs.readFileSync(0, 'utf8').replace(/[\\r\\n]+$/, '') : undefined;
fs.appendFileSync(process.env.MOCK_CALLS, JSON.stringify({ args, password }) + '\\n');
if (args.includes('-validate-password')) {
    if (process.env.FAIL_VALIDATION) process.exit(Number(process.env.FAIL_VALIDATION));
    if ([...password].length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
        process.stderr.write('密码至少需要 8 个字符，且 UTF-8 编码后不能超过 72 字节\\n');
        process.exit(1);
    }
} else if (args.includes('-username') && process.env.FAIL_ACCOUNT) {
    process.stderr.write('账户保存失败\\n');
    process.exit(1);
} else if (args.includes('-port') && process.env.FAIL_PORT) {
    process.stderr.write('端口保存失败\\n');
    process.exit(1);
}
`);
    const source = mode === 'install' ? installer : manager;
    const action = mode === 'install' ? 'config_after_install' : 'reset_user';
    const functions = [extract(source, 'read_account_password'), extract(source, action)]
        .join('\n').replaceAll('/usr/local/x-ui/x-ui', 'mock_x_ui');
    const result = spawnSync('bash', ['-c', `
mock_x_ui() { "$MOCK_NODE" "$MOCK_PROGRAM" "$@"; }
confirm() { return 0; }
confirm_restart() { echo RESTART_REQUESTED; }
show_menu() { echo MENU_REQUESTED; }
${functions}
${action} test
`], {
        input,
        encoding: 'utf8',
        timeout: 5000,
        env: {
            ...process.env,
            LC_ALL: 'C',
            MOCK_NODE: process.execPath,
            MOCK_PROGRAM: program,
            MOCK_CALLS: callsPath,
            ...failures,
        },
    });
    assert.ifError(result.error);
    const calls = fs.existsSync(callsPath)
        ? fs.readFileSync(callsPath, 'utf8').trim().split('\n').map(JSON.parse) : [];
    return { ...result, calls, output: result.stdout + result.stderr };
}

function accountCalls(result) {
    return result.calls.filter(call => call.args.includes('-username'));
}

function validationCalls(result) {
    return result.calls.filter(call => call.args.includes('-validate-password'));
}

function assertNoSecretOutput(result, passwords) {
    for (const password of passwords) {
        assert.ok(!result.output.includes(password), 'password must not be printed');
        assert.ok(result.calls.every(call => !call.args.includes(password)), 'password must not appear in command arguments');
    }
}

test('installer and manager share the same eight-character password input policy', () => {
    assert.equal(extract(installer, 'read_account_password'), extract(manager, 'read_account_password'));
    for (const source of [installer, manager]) {
        assert.match(source, /至少 8 个字符，UTF-8 编码后最多 72 字节/);
        assert.doesNotMatch(source, /至少 12 位/);
    }
    assert.match(installer, /config_after_install \|\| exit 1/);
});

test('login and account settings preserve passwords and show the eight-character policy', () => {
    const login = fs.readFileSync(path.join(root, 'web/html/login.html'), 'utf8');
    const settings = fs.readFileSync(path.join(root, 'web/html/xui/setting.html'), 'utf8');
    assert.match(login, /v-model="user\.password"/);
    assert.doesNotMatch(login, /v-model\.trim="user\.password"/);
    assert.match(settings, /v-model="user\.oldPassword"/);
    assert.match(settings, /v-model="user\.newPassword"/);
    assert.match(settings, /至少 8 个字符，UTF-8 编码后不超过 72 字节/);
});

for (const mode of ['install', 'reset']) {
    function inputFor(passwords, username = 'operator') {
        return `${mode === 'install' ? 'y\n' : ''}${username}\n${passwords.join('\n')}\n${mode === 'install' ? '54321\n' : ''}`;
    }

    test(`${mode}: seven-character password warns and retries, eight characters saves`, t => {
        const passwords = ['aB3!xYz', 'aB3!xYz8'];
        const result = runScript(t, mode, inputFor(passwords));
        assert.equal(result.status, 0, result.output);
        assert.match(result.output, /密码至少需要 8 个字符/);
        assert.match(result.output, /密码不符合要求，请重新输入/);
        assert.deepEqual(validationCalls(result).map(call => call.password), passwords);
        assert.deepEqual(accountCalls(result).map(call => call.password), [passwords[1]]);
        assertNoSecretOutput(result, passwords);
    });

    test(`${mode}: empty password retries and does not update the account`, t => {
        const result = runScript(t, mode, inputFor(['', 'Valid!88']));
        assert.equal(result.status, 0, result.output);
        assert.equal(validationCalls(result).length, 2);
        assert.deepEqual(accountCalls(result).map(call => call.password), ['Valid!88']);
    });

    test(`${mode}: username still trims surrounding spaces to match the login form`, t => {
        const result = runScript(t, mode, inputFor(['Valid!88'], ' operator '));
        assert.equal(result.status, 0, result.output);
        const args = accountCalls(result)[0].args;
        assert.equal(args[args.indexOf('-username') + 1], 'operator');
    });

    test(`${mode}: Unicode, backslashes and surrounding spaces are preserved under C locale`, t => {
        const password = ' 空 格\\密碼  ';
        const result = runScript(t, mode, inputFor([password]));
        assert.equal(result.status, 0, result.output);
        assert.deepEqual(accountCalls(result).map(call => call.password), [password]);
        assertNoSecretOutput(result, [password]);
    });

    test(`${mode}: multibyte passwords exceeding 72 bytes retry before save`, t => {
        const passwords = ['密'.repeat(25), '密'.repeat(24)];
        const result = runScript(t, mode, inputFor(passwords));
        assert.equal(result.status, 0, result.output);
        assert.match(result.output, /不能超过 72 字节/);
        assert.deepEqual(accountCalls(result).map(call => call.password), [passwords[1]]);
        assertNoSecretOutput(result, passwords);
    });

    test(`${mode}: EOF after an invalid password cancels without save or restart`, t => {
        const input = `${mode === 'install' ? 'y\n' : ''}operator\naB3!xYz\n`;
        const result = runScript(t, mode, input);
        assert.equal(result.status, 1, result.output);
        assert.match(result.output, /输入已结束，已取消密码设置/);
        assert.equal(accountCalls(result).length, 0);
        assert.doesNotMatch(result.output, /设定完成|已安全重置|RESTART_REQUESTED/);
        assertNoSecretOutput(result, ['aB3!xYz']);
    });

    test(`${mode}: EOF while reading username cancels without changing settings`, t => {
        const result = runScript(t, mode, mode === 'install' ? 'y\n' : '');
        assert.equal(result.status, 1, result.output);
        assert.equal(result.calls.length, 0);
        assert.match(result.output, /输入已结束，已取消账户配置/);
    });

    test(`${mode}: unavailable validator stops instead of retrying indefinitely`, t => {
        const result = runScript(t, mode, inputFor(['Valid!88', 'Other!88']), { FAIL_VALIDATION: '2' });
        assert.equal(result.status, 1, result.output);
        assert.equal(validationCalls(result).length, 1);
        assert.equal(accountCalls(result).length, 0);
        assert.match(result.output, /面板程序与安装脚本版本一致/);
        assert.doesNotMatch(result.output, /设定完成|已安全重置|RESTART_REQUESTED/);
    });

    test(`${mode}: failed account save never reports success or requests restart`, t => {
        const result = runScript(t, mode, inputFor(['Valid!88']), { FAIL_ACCOUNT: '1' });
        assert.equal(result.status, 1, result.output);
        assert.equal(accountCalls(result).length, 1);
        assert.ok(result.calls.every(call => !call.args.includes('-port')));
        assert.match(result.output, /账户密码设置失败/);
        assert.doesNotMatch(result.output, /设定完成|已安全重置|RESTART_REQUESTED/);
        assertNoSecretOutput(result, ['Valid!88']);
    });
}

test('install: EOF during confirmation safely aborts', t => {
    const result = runScript(t, 'install', '');
    assert.equal(result.status, 1, result.output);
    assert.equal(result.calls.length, 0);
    assert.match(result.output, /输入已结束，已取消账户配置/);
});

test('install: EOF while reading the port does not partially save the account', t => {
    const result = runScript(t, 'install', 'y\noperator\nValid!88\n');
    assert.equal(result.status, 1, result.output);
    assert.equal(accountCalls(result).length, 0);
    assert.match(result.output, /输入已结束，已取消账户配置/);
});

test('install: failed port save returns failure and does not report port success', t => {
    const result = runScript(t, 'install', 'y\noperator\nValid!88\n54321\n', { FAIL_PORT: '1' });
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, /面板端口设置失败/);
    assert.doesNotMatch(result.output, /面板端口设定完成/);
});
