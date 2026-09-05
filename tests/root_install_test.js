const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const installer = fs.readFileSync(path.join(root, 'install.sh'), 'utf8');
const manager = fs.readFileSync(path.join(root, 'x-ui.sh'), 'utf8');
// Extract only this self-contained helper: never source the installer or touch
// the host's service manager, accounts, application or configuration paths.
const migration = installer.match(/^migrate_legacy_tun_dropin\(\) \{[\s\S]*?^\}/m)?.[0];
assert.ok(migration, 'installer exposes its migration helper');
const archiveValidation = installer.match(/^validate_root_service_archive\(\) \{[\s\S]*?^\}/m)?.[0];
assert.ok(archiveValidation, 'installer validates the root service contract');
const legacyDropIn = '# Managed by bx-ui tun enable. Remove using bx-ui tun disable.\n'
    + '[Service]\n'
    + 'PrivateDevices=false\n'
    + 'DevicePolicy=closed\n'
    + 'DeviceAllow=/dev/net/tun rw\n'
    + 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n'
    + 'AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n';

function fixture(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bx-ui-root-install-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return { directory, target: path.join(directory, '50-bx-ui-tun.conf') };
}

function migrate(directory, check = false) {
    return spawnSync('bash', ['-c', `${migration}\nmigrate_legacy_tun_dropin "$1" "$2"`,
        'migration-test', directory, check ? '--check' : ''], { encoding: 'utf8' });
}

function validateArchive(archive) {
    return spawnSync('bash', ['-c', `${archiveValidation}\nvalidate_root_service_archive "$1"`,
        'archive-test', archive], { encoding: 'utf8' });
}

function createArchive(t, serviceContents) {
    const { directory } = fixture(t);
    const application = path.join(directory, 'x-ui');
    fs.mkdirSync(application);
    if (serviceContents !== null) {
        fs.writeFileSync(path.join(application, 'x-ui.service'), serviceContents);
    }
    const archive = path.join(directory, 'release.tar.gz');
    const result = spawnSync('tar', ['-czf', archive, '-C', directory, 'x-ui'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return archive;
}

test('installer and management scripts retain root-only entry points', () => {
    for (const source of [installer, manager]) {
        assert.match(source, /\[\[ \$EUID -ne 0 \]\].*exit 1/);
        assert.doesNotMatch(source, /\b(?:useradd|groupadd|userdel|groupdel)\b/);
        assert.doesNotMatch(source, /(?:root:x-ui|x-ui:x-ui|chmod 0775)/);
    }
});

test('installation owns application files as root without group-writable directories', () => {
    assert.match(installer, /chown -R root:root \/usr\/local\/x-ui \/etc\/x-ui/);
    assert.match(installer, /find \/usr\/local\/x-ui -type d -exec chmod 0755/);
    assert.match(installer, /find \/usr\/local\/x-ui -type f -exec chmod go-w/);
    assert.match(installer, /install -o root -g root -m 0644 x-ui\.service/);
    for (const source of [installer, manager]) {
        assert.match(source, /install -o root -g root -m 0755 \/usr\/local\/x-ui\/x-ui\.sh \/usr\/bin\/x-ui/);
    }
});

test('root extraction never restores the builder UID or permissive archive modes', () => {
    assert.match(installer, /^umask 077$/m);
    assert.match(installer, /tar --no-same-owner --no-same-permissions -zxvf "\$\{archive\}" \|\| exit 1/);
    const releaseWorkflow = fs.readFileSync(path.join(root, '.github/workflows/release.yml'), 'utf8');
    assert.match(releaseWorkflow, /tar --owner=0 --group=0 -C dist -czf/);
});

test('service operations cannot silently continue after migration errors', () => {
    assert.match(installer, /if ! systemctl stop x-ui; then[\s\S]*?LoadState=not-found[\s\S]*?exit 1/);
    for (const operation of ['daemon-reload', 'enable x-ui', 'start x-ui']) {
        assert.ok(installer.includes(`systemctl ${operation} || exit 1`), operation);
    }
});

test('upgrade preserves the database and restricts sensitive configuration permissions', () => {
    assert.match(installer, /\[\[ -s \/etc\/x-ui\/x-ui\.db \]\][\s\S]*?is_upgrade=true/);
    assert.match(installer, /if \[\[ "\$\{is_upgrade\}" == "false" \]\]; then\s+config_after_install/);
    assert.doesNotMatch(installer, /rm[^\n]*\/etc\/x-ui/);
    assert.match(installer, /find \/etc\/x-ui -type d -exec chmod 0700/);
    assert.match(installer, /find \/etc\/x-ui -type f -exec chmod 0600/);
});

test('migration checks before stopping the service and removes only after replacing the unit', () => {
    const archiveCheck = installer.indexOf('validate_root_service_archive "${archive}" || exit 1');
    const check = installer.indexOf('migrate_legacy_tun_dropin /etc/systemd/system/x-ui.service.d --check || exit 1');
    const stop = installer.indexOf('systemctl stop x-ui');
    const installUnit = installer.indexOf('install -o root -g root -m 0644 x-ui.service');
    const cleanup = installer.indexOf('migrate_legacy_tun_dropin || exit 1');
    const reload = installer.indexOf('systemctl daemon-reload');
    assert.ok(archiveCheck >= 0 && archiveCheck < check && check < stop && stop < installUnit && installUnit < cleanup && cleanup < reload);
});

test('installer accepts a verified archive whose service runs as root', t => {
    const archive = createArchive(t, '[Unit]\nDescription=bx-ui\n[Service]\nUser=root\nGroup=root\n');
    assert.equal(validateArchive(archive).status, 0);
});

for (const [name, service] of [
    ['an older unprivileged release', '[Service]\nUser=x-ui\nGroup=x-ui\n'],
    ['missing explicit root group', '[Service]\nUser=root\n'],
    ['later overriding user', '[Service]\nUser=root\nGroup=root\nUser=x-ui\n'],
    ['root directives in the wrong section', '[Unit]\nUser=root\nGroup=root\n[Service]\nExecStart=/bin/true\n'],
    ['empty service', ''],
]) {
    test(`installer rejects ${name} before any service change`, t => {
        const result = validateArchive(createArchive(t, service));
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stderr, /0\.4\.8/);
        assert.match(result.stderr, /未停止现有面板/);
    });
}

test('installer rejects archives without a readable service unit', t => {
    const archive = createArchive(t, null);
    assert.equal(validateArchive(archive).status, 1);
    fs.writeFileSync(archive, 'not an archive');
    assert.equal(validateArchive(archive).status, 1);
});

test('migration tolerates a missing managed file and absent configuration directory', t => {
    const { directory } = fixture(t);
    assert.equal(migrate(directory).status, 0);
    assert.equal(migrate(path.join(directory, 'missing')).status, 0);
    assert.deepEqual(fs.readdirSync(directory), []);
});

test('migration preflight leaves the exact old managed file untouched, then removal is idempotent', t => {
    const { directory, target } = fixture(t);
    fs.writeFileSync(target, legacyDropIn);
    const other = path.join(directory, '90-custom.conf');
    fs.writeFileSync(other, '[Service]\nEnvironment=KEEP=yes\n');
    assert.equal(migrate(directory, true).status, 0);
    assert.equal(fs.readFileSync(target, 'utf8'), legacyDropIn);
    assert.equal(migrate(directory).status, 0);
    assert.equal(fs.existsSync(target), false);
    assert.equal(fs.readFileSync(other, 'utf8'), '[Service]\nEnvironment=KEEP=yes\n');
    assert.equal(migrate(directory).status, 0);
});

for (const [name, contents] of [
    ['custom capability list', legacyDropIn.replace('CAP_NET_ADMIN', 'CAP_SYS_ADMIN')],
    ['extra trailing newline', `${legacyDropIn}\n`],
    ['missing trailing newline', legacyDropIn.trimEnd()],
    ['empty file', ''],
]) {
    test(`migration refuses and preserves ${name}`, t => {
        const { directory, target } = fixture(t);
        fs.writeFileSync(target, contents);
        for (const check of [true, false]) {
            const result = migrate(directory, check);
            assert.equal(result.status, 1, result.stderr);
            assert.match(result.stderr, /已保留/);
            assert.equal(fs.readFileSync(target, 'utf8'), contents);
        }
    });
}

test('migration refuses a symlink even when its target is the exact old managed content', t => {
    const { directory, target } = fixture(t);
    const original = path.join(directory, 'original.conf');
    fs.writeFileSync(original, legacyDropIn);
    fs.symlinkSync(original, target);
    assert.equal(migrate(directory).status, 1);
    assert.equal(fs.lstatSync(target).isSymbolicLink(), true);
    assert.equal(fs.readFileSync(original, 'utf8'), legacyDropIn);
});

test('migration refuses a dangling symlink or directory in place of the managed file', t => {
    const { directory, target } = fixture(t);
    fs.symlinkSync(path.join(directory, 'missing'), target);
    assert.equal(migrate(directory).status, 1);
    assert.equal(fs.lstatSync(target).isSymbolicLink(), true);
    fs.unlinkSync(target);
    fs.mkdirSync(target);
    assert.equal(migrate(directory).status, 1);
    assert.equal(fs.statSync(target).isDirectory(), true);
});

test('migration refuses a symlinked configuration directory', t => {
    const { directory } = fixture(t);
    const actual = path.join(directory, 'actual');
    fs.mkdirSync(actual);
    const target = path.join(actual, '50-bx-ui-tun.conf');
    fs.writeFileSync(target, legacyDropIn);
    const link = path.join(directory, 'link');
    fs.symlinkSync(actual, link);
    assert.equal(migrate(link).status, 1);
    assert.equal(fs.readFileSync(target, 'utf8'), legacyDropIn);
});
