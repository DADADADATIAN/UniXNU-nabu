"""Provision directories and links on the verified volatile Data mount before Apple init.

The list mirrors the reference Data layout shipped in the 21H16 OS image
(/private/var on the restore volume), read with apfs-fuse on 2026-10-26:
modes and numeric owners are the image's, and the two timezone links match
that image's /Library/Preferences and /usr/share/zoneinfo indirection.
"""
import hashlib
import plistlib

from nabu_graphics_startup import _recount_hunks, _replace_once

DATA_PATCH = 'patches/xnu/zzzz-nabu-data-skeleton.patch'

# Parents precede their children. The reference image ships /private/var with
# these entries; services such as init_featureflags reach them through the
# /Library and /usr/share symlinks on the read-only OS volume.
DIRECTORIES = (
    ('audit', 0o700, 0, 0),
    ('buddy', 0o700, 501, 501),
    ('containers', 0o755, 0, 0),
    ('containers/Bundle', 0o755, 0, 0),
    ('containers/Data', 0o755, 0, 0),
    ('containers/Data/Application', 0o755, 0, 0),
    ('containers/Data/System', 0o755, 0, 0),
    ('containers/Shared', 0o755, 0, 0),
    ('containers/Shared/SystemGroup', 0o755, 0, 0),
    ('containers/Temp', 0o755, 0, 0),
    ('cores', 0o755, 0, 0),
    ('datamigrator', 0o755, 501, 501),
    ('db', 0o755, 0, 0),
    ('db/dslocal', 0o755, 0, 0),
    ('db/dslocal/nodes', 0o755, 0, 0),
    ('db/dslocal/nodes/Default', 0o755, 0, 0),
    ('db/dslocal/nodes/Default/config', 0o755, 0, 0),
    ('db/dslocal/nodes/Default/groups', 0o755, 0, 0),
    ('db/dslocal/nodes/Default/users', 0o755, 0, 0),
    ('db/com.apple.xpc.launchd', 0o755, 0, 0),
    ('db/com.apple.xpc.roleaccountd.staging', 0o700, 0, 0),
    ('db/Sandbox', 0o700, 0, 0),
    ('db/accessoryupdater', 0o751, 278, 278),
    ('db/analyticsd', 0o750, 263, 263),
    ('db/astris', 0o755, 245, 245),
    ('db/biome', 0o751, 501, 501),
    ('db/com.apple.dt.automationmode', 0o755, 0, 0),
    ('db/com.apple.findmy.findmybeaconingd', 0o755, 501, 501),
    ('db/coreml', 0o750, 280, 280),
    ('db/darwindaemon', 0o750, 284, 284),
    ('db/datadetectors', 0o711, 257, 257),
    ('db/diagnostics', 0o751, 272, 272),
    ('db/diskimagesiod', 0o750, 271, 271),
    ('db/DumpPanic', 0o755, 0, 0),
    ('db/eligibilityd', 0o755, 297, 297),
    ('db/ExtensibleSSO', 0o755, 0, 0),
    ('db/findmydevice', 0o755, 254, 254),
    ('db/fpsd', 0o750, 501, 501),
    ('db/gpsd', 0o700, 267, 267),
    ('db/knowledgegraphd', 0o750, 279, 279),
    ('db/lockdown', 0o700, 213, 213),
    ('db/lsd', 0o755, 501, 501),
    ('db/mmaintenanced', 0o750, 283, 283),
    ('db/nearbyd', 0o750, 501, 501),
    ('db/ondemand', 0o755, 249, 249),
    ('db/os_eligibility', 0o755, 297, 297),
    ('db/reportmemoryexception', 0o750, 269, 269),
    ('db/rmd', 0o750, 277, 277),
    ('db/sysdiagnose', 0o755, 0, 0),
    ('db/systemstats', 0o755, 0, 0),
    ('db/timed', 0o750, 266, 266),
    ('db/timezone', 0o755, 0, 0),
    ('db/timezone/tz', 0o755, 0, 0),
    ('db/UpdateMetrics', 0o777, 501, 501),
    ('dextcores', 0o755, 270, 270),
    ('empty', 0o755, 0, 3),
    ('folders', 0o755, 0, 0),
    ('hardware', 0o755, 0, 0),
    ('installd', 0o755, 33, 33),
    ('keybags', 0o700, 0, 0),
    ('keybags/backup', 0o700, 0, 0),
    ('Keychains', 0o755, 64, 0),
    ('log', 0o755, 0, 0),
    ('log/com.apple.xpc.launchd', 0o755, 0, 0),
    ('logs', 0o755, 0, 0),
    ('Managed Preferences', 0o755, 0, 0),
    ('Managed Preferences/mobile', 0o755, 501, 501),
    ('mobile', 0o711, 501, 501),
    ('mobile/Containers', 0o755, 501, 501),
    ('mobile/Documents', 0o755, 501, 501),
    ('mobile/Library', 0o755, 501, 501),
    ('mobile/Library/Caches', 0o755, 501, 501),
    ('mobile/Library/Logs', 0o755, 501, 501),
    ('mobile/Library/Preferences', 0o755, 501, 501),
    ('mobile/Media', 0o755, 501, 501),
    ('mobile/tmp', 0o700, 501, 501),
    ('MobileAsset', 0o755, 0, 0),
    ('MobileDevice', 0o755, 0, 0),
    ('MobileSoftwareUpdate', 0o755, 0, 0),
    ('msgs', 0o755, 0, 0),
    ('networkd', 0o755, 24, 0),
    ('OOPJit', 0o777, 0, 80),
    ('PersonaVolumes', 0o755, 0, 0),
    ('preboot', 0o755, 0, 0),
    ('preferences', 0o755, 0, 0),
    ('protected', 0o755, 0, 0),
    ('root', 0o755, 0, 0),
    ('root/Library', 0o755, 0, 0),
    ('root/Library/Preferences', 0o755, 0, 0),
    ('run', 0o775, 0, 1),
    ('select', 0o755, 0, 0),
    ('staged_system_apps', 0o755, 501, 501),
    ('tmp', 0o1777, 0, 0),
    ('vm', 0o755, 0, 0),
    ('wireless', 0o755, 25, 25),
)

# The OS image ships /usr/share/zoneinfo -> /var/db/timezone/zoneinfo and
# /private/var/db/timezone/localtime -> /var/db/timezone/zoneinfo/US/Pacific.
# Without the first link both are dangling and tzinit fails its system-partition
# fallback, so the skeleton creates the pair the restore image expects.
SYMLINKS = (
    ('db/timezone/zoneinfo', '/usr/share/zoneinfo.default'),
    ('db/timezone/localtime', '/var/db/timezone/zoneinfo/US/Pacific'),
)

# Opt-in (nabu-disable-watchdogd=1), following UniXNU's sheng-disable-watchdogd:
# launchd's own root-owned override database disables the watchdogd job; the
# existing migration marker selects launchd's direct disabled.plist path.
WATCHDOGD_DISABLED = plistlib.dumps({'com.apple.watchdogd': True})
LAUNCHD_FILES = (
    ('db/com.apple.xpc.launchd/disabled.plist', WATCHDOGD_DISABLED),
    ('db/com.apple.xpc.launchd/disabled.migrated', b''),
)

# Opt-in (nabu-skip-setup=1): UniXNU scripts/seed-data-skip-setup.py --no-auto-dim
# preferences, so Setup (purplebuddy) does not run as the alternate system app
# that blocks SpringBoard. XML plists, owned by mobile with mode 0600.
BUILD = '21H16'
SETUP_PREFERENCES = (
    ('com.apple.migration', {
        'LastSystemVersion': BUILD,
        'DMUserDataDisposition': {'SyntheticDidUpgrade': False, 'buildVersion': BUILD}}),
    ('com.apple.springboard', {
        'BKNoWatchdogs': True,
        'FBLaunchWatchdogExceptions': {'com.apple.purplebuddy': 100.0},
        'MCForceShowCloudConfigurationUI': False,
        'SBDisableAutoDim': True, 'SBDontDimOrLockOnAC': True, 'SBDisableIdleSleep': True}),
    ('com.apple.purplebuddy', {
        'SetupDone': True, 'SetupFinishedAllSteps': True, 'SetupVersion': 11, 'daemonizeNeedsToRun': False}),
    ('com.apple.purplebuddy.notbackedup', {
        key: False for key in ('ShouldRunDiagnosticsMiniBuddy', 'ShouldRunHSA2MiniBuddy',
                               'ShouldRunKeychainSyncMiniBuddy', 'ShouldRunMesaMiniBuddy',
                               'ShouldRunPaymentMiniBuddy', 'ShouldRunStandardMiniBuddy',
                               'SilentICDPUpgrade')}),
    ('com.apple.managedconfiguration.notbackedup', {
        'LockdownActivationIndicatesCloudConfigurationAvailable': False}),
)
SETUP_FILES = tuple(('mobile/Library/Preferences/' + name + '.plist', plistlib.dumps(values))
                    for name, values in SETUP_PREFERENCES)

# Opt-in (nabu-cpu-present=1), as UniXNU scripts/add-gpu-plugin-data.py: the render
# server (backboardd) picks a 10-bit deep, compressed framebuffer unless told not
# to, read at process start. The CPU copy presents plain BGRA only. Both its own
# domain and the global fallback, for mobile and root, mode 0644.
FRAMEBUFFER_PREFERENCES = plistlib.dumps({
    'CAEnableDeepFramebuffer': False, 'CAEnableFramebufferCompression': False,
    'CAEnableIOSurfaceCompression': False})
FRAMEBUFFER_FILES = tuple((home + '/Library/Preferences/' + name, FRAMEBUFFER_PREFERENCES, uid)
                          for home, uid in (('mobile', 501), ('root', 0))
                          for name in ('backboardd.plist', '.GlobalPreferences.plist'))


def _c_string(data):
    text = data.decode('ascii')
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t') + '"'


AFTER_DATA = '''#if (DEVELOPMENT || DEBUG) && defined(XNU_NATIVE_LEGACY_DISPLAY) && XNU_NATIVE_LEGACY_DISPLAY
\tif (!error) {
\t\textern void nabu_graphics_start_after_root(void);
\t\tnabu_graphics_start_after_root();
\t}
#endif
'''

HELPER = r'''static int
native_owner_data_mkdir(proc_t p, user_addr_t scratch, mount_t data_mount,
    const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp = NULLVP;
	int error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (!error) {
		error = vnode_vtype(vp) != VDIR ? ENOTDIR :
		    (vnode_mount(vp) != data_mount ? EXDEV : 0);
		vnode_put(vp);
		return error;
	}
	if (error != ENOENT) return error;
	char parent[160];
	if (strlen(path) >= sizeof(parent)) return ENAMETOOLONG;
	strlcpy(parent, path, sizeof(parent));
	char *slash = strrchr(parent, '/');
	if (!slash || slash == parent) return EINVAL;
	*slash = 0;
	error = vnode_lookup(parent, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (error) return error;
	error = vnode_vtype(vp) != VDIR ? ENOTDIR :
	    (vnode_mount(vp) != data_mount ? EXDEV : 0);
	vnode_put(vp);
	if (error) return error;
	/* Use the regular VFS mkdir path and the existing 4 KiB init scratch. */
	struct mkdir_args request = {.path = scratch + 0xa00, .mode = mode};
	int32_t result = 0;
	error = copyout(path, request.path, strlen(path) + 1);
	if (!error) error = mkdir(p, &request, &result);
	if (error) return error;
	error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (error) return error;
	if (vnode_vtype(vp) != VDIR || vnode_mount(vp) != data_mount) {
		vnode_put(vp);
		return EXDEV;
	}
	struct vnode_attr va;
	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, mode);
	VATTR_SET(&va, va_uid, uid);
	VATTR_SET(&va, va_gid, gid);
	error = vnode_setattr(vp, &va, ctx);
	vnode_put(vp);
	return error;
}

static int
native_owner_data_symlink(proc_t p, user_addr_t scratch, mount_t data_mount,
    const char *path, const char *target)
{
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp = NULLVP;
	int error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (!error) {
		/* Reuse is accepted only for an existing link on the Data mount. */
		error = vnode_vtype(vp) != VLNK ? EEXIST :
		    (vnode_mount(vp) != data_mount ? EXDEV : 0);
		vnode_put(vp);
		return error;
	}
	if (error != ENOENT) return error;
	char parent[160];
	if (strlen(path) >= sizeof(parent)) return ENAMETOOLONG;
	strlcpy(parent, path, sizeof(parent));
	char *slash = strrchr(parent, '/');
	if (!slash || slash == parent) return EINVAL;
	*slash = 0;
	error = vnode_lookup(parent, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (error) return error;
	error = vnode_vtype(vp) != VDIR ? ENOTDIR :
	    (vnode_mount(vp) != data_mount ? EXDEV : 0);
	vnode_put(vp);
	if (error) return error;
	struct symlink_args request = {.path = scratch + 0xa00, .link = scratch + 0xb00};
	int32_t result = 0;
	/* symlinkat_internal: path_data is the target, link is the new path. */
	error = copyout(target, request.path, strlen(target) + 1);
	if (!error) error = copyout(path, request.link, strlen(path) + 1);
	if (!error) error = symlink(p, &request, &result);
	return error;
}

static int
native_owner_data_file(mount_t data_mount, const char *path, const char *data, size_t size,
    mode_t mode, uid_t uid, gid_t gid)
{
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp = NULLVP;
	int error = vnode_open(path, O_CREAT | O_TRUNC | FWRITE | O_NOFOLLOW, mode, 0, &vp, ctx);
	if (error) return error;
	error = vnode_vtype(vp) != VREG ? EFTYPE :
	    (vnode_mount(vp) != data_mount ? EXDEV : 0);
	if (!error && size) {
		int resid = 0;
		error = vn_rdwr(UIO_WRITE, vp, (caddr_t)(uintptr_t)data, (int)size, 0, UIO_SYSSPACE,
		    IO_NOAUTH | IO_UNIT, vfs_context_ucred(ctx), &resid, vfs_context_proc(ctx));
		if (!error && resid) error = EIO;
	}
	if (!error) {
		struct vnode_attr va;
		VATTR_INIT(&va);
		VATTR_SET(&va, va_mode, mode);
		VATTR_SET(&va, va_uid, uid);
		VATTR_SET(&va, va_gid, gid);
		error = vnode_setattr(vp, &va, ctx);
	}
	int closed = vnode_close(vp, FWRITE, ctx);
	return error ? error : closed;
}

static int
native_owner_data_skeleton(proc_t p, user_addr_t scratch, mount_t data_mount)
{
	static const struct {
		const char *path;
		mode_t mode;
		uid_t uid;
		gid_t gid;
	} dirs[] = {
__DIRECTORIES__
	};
	static const struct {
		const char *path;
		const char *target;
	} links[] = {
__SYMLINKS__
	};
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
		int error = native_owner_data_mkdir(p, scratch, data_mount,
		    dirs[i].path, dirs[i].mode, dirs[i].uid, dirs[i].gid);
		if (error) {
			printf("NABU DATA: skeleton failed path=%s error=%d\n", dirs[i].path, error);
			return error;
		}
	}
	for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); ++i) {
		int error = native_owner_data_symlink(p, scratch, data_mount,
		    links[i].path, links[i].target);
		if (error) {
			printf("NABU DATA: skeleton link failed path=%s error=%d\n", links[i].path, error);
			return error;
		}
	}
	printf("NABU DATA: skeleton ready dirs=%lu links=%lu\n",
	    (unsigned long)(sizeof(dirs) / sizeof(dirs[0])),
	    (unsigned long)(sizeof(links) / sizeof(links[0])));
	static const struct {
		const char *gate;
		const char *path;
		const char *data;
		size_t size;
		mode_t mode;
		uid_t uid;
		gid_t gid;
	} files[] = {
__FILES__
	};
	unsigned disable_watchdogd = 0, skip_setup = 0, cpu_present = 0;
	if (!PE_parse_boot_argn("nabu-disable-watchdogd", &disable_watchdogd, sizeof(disable_watchdogd)))
		disable_watchdogd = 0;
	if (!PE_parse_boot_argn("nabu-skip-setup", &skip_setup, sizeof(skip_setup)))
		skip_setup = 0;
	if (!PE_parse_boot_argn("nabu-cpu-present", &cpu_present, sizeof(cpu_present)))
		cpu_present = 0;
	for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
		unsigned enabled = files[i].gate[0] == 'w' ? disable_watchdogd :
		    files[i].gate[0] == 'c' ? cpu_present : skip_setup;
		if (enabled != 1) continue;
		int error = native_owner_data_file(data_mount, files[i].path, files[i].data, files[i].size,
		    files[i].mode, files[i].uid, files[i].gid);
		if (error) {
			printf("NABU DATA: seeded file failed path=%s error=%d\n", files[i].path, error);
			return error;
		}
	}
	if (disable_watchdogd == 1) printf("NABU DATA: launchd override disables com.apple.watchdogd\n");
	if (skip_setup == 1) printf("NABU DATA: Setup preferences seeded (SetupDone, no auto-dim)\n");
	if (cpu_present == 1) printf("NABU DATA: framebuffer preferences seeded (no deep/compressed)\n");
	return 0;
}

'''


def helper_source():
    rows = '\n'.join(f'\t\t{{ "/private/var/{path}", 0{mode:o}, {uid}, {gid} }},'
                     for path, mode, uid, gid in DIRECTORIES)
    links = '\n'.join(f'\t\t{{ "/private/var/{path}", "{target}" }},'
                      for path, target in SYMLINKS)
    # launchd accepts its override database only from root with mode 0644;
    # preferences belong to mobile (UniXNU writes them with mode 0600).
    seeded = [('watchdogd', path, content, 0o644, 0, 0) for path, content in LAUNCHD_FILES]
    seeded += [('setup', path, content, 0o600, 501, 501) for path, content in SETUP_FILES]
    seeded += [('cpu', path, content, 0o644, uid, uid) for path, content, uid in FRAMEBUFFER_FILES]
    files = '\n'.join(f'\t\t{{ "{gate}", "/private/var/{path}", {_c_string(content)}, {len(content)}, '
                      f'0{mode:o}, {uid}, {gid} }},'
                      for gate, path, content, mode, uid, gid in seeded)
    return (HELPER.replace('__DIRECTORIES__', rows)
            .replace('__SYMLINKS__', links)
            .replace('__FILES__', files))


def add_data_skeleton(text):
    anchor = 'static int\nnative_owner_data_prepare(proc_t p, user_addr_t scratch)\n'
    text = _replace_once(text, anchor, helper_source() + anchor)
    marker = '\tif (!error) native_owner_data_stage = 4;\n'
    text = _replace_once(text, marker,
                         '\tif (!error) error = native_owner_data_skeleton(p, scratch, data_mount);\n' + marker)
    end = '\tnative_owner_data_status = error;\n\treturn error;\n'
    text = _replace_once(text, end, '\tnative_owner_data_status = error;\n' + AFTER_DATA + '\treturn error;\n')
    return text


def skeleton_patch():
    helper = ''.join('+' + line + '\n' for line in helper_source().splitlines())
    patch = ('--- a/bsd/kern/kern_exec.c\n+++ b/bsd/kern/kern_exec.c\n'
             '@@ -7824,3 +7824,3 @@\n' + helper +
             ' static int\n native_owner_data_prepare(proc_t p, user_addr_t scratch)\n {\n'
             '@@ -7879,6 +7879,7 @@\n'
             ' \tif (actual != device || (vfs_flags(data_mount) & MNT_RDONLY) ||\n'
             ' \t    strcmp(vfs_statfs(data_mount)->f_fstypename, "apfs")) error = EINVAL;\n'
             '+\tif (!error) error = native_owner_data_skeleton(p, scratch, data_mount);\n'
             ' \tif (!error) native_owner_data_stage = 4;\n'
             ' \tif (!error) native_gpu_addon_prepare(p, scratch);\n'
             ' \tif (!error) native_staged_apps_prepare(p, scratch, data_mount);\n'
             ' done:\n'
             '@@ -7886,5 +7886,5 @@\n'
             ' \tif (data_root) vnode_put(data_root);\n'
             ' \tnative_owner_data_status = error;\n' +
             ''.join('+' + line + '\n' for line in AFTER_DATA.splitlines()) +
             ' \treturn error;\n }\n #endif\n')
    return _recount_hunks(patch).encode('utf-8')


def wire_graphics_compile_flag(text):
    anchor = 'EXTRA_MAKE_ARGS+=("kern_exec.o_CFLAGS_ADD='
    return _replace_once(text, anchor,
                         anchor + '-DXNU_NATIVE_LEGACY_DISPLAY=${XNU_NATIVE_LEGACY_DISPLAY:-0} ')


def prepare_data_skeleton(upstream):
    path = upstream / DATA_PATCH
    if path.exists():
        raise ValueError('Data skeleton patch already exists; prepare a fresh source tree')
    build = upstream / 'scripts/build-xnu-4k-baseline.sh'
    text = build.read_text(encoding='utf-8')
    old = 'for LATE_PATCH in "$ROOT/patches/xnu/zzz-boot-progress.patch"'
    new = 'for LATE_PATCH in "$ROOT/' + DATA_PATCH + '" "$ROOT/patches/xnu/zzz-boot-progress.patch"'
    text = _replace_once(text, old, new)
    text = wire_graphics_compile_flag(text)
    after = skeleton_patch()
    path.write_bytes(after)
    build.write_text(text, encoding='utf-8')
    return {'patch': DATA_PATCH, 'after_sha256': hashlib.sha256(after).hexdigest(),
            'directories': [row[0] for row in DIRECTORIES],
            'symlinks': [{'path': path, 'target': target} for path, target in SYMLINKS],
            'reference': '21H16 restore-image /private/var (apfs-fuse, 2026-10-26)',
            'runtime_qualified': False}


def qualify_data_skeleton(upstream, prepared, *, capture_logs=False):
    """Check the enabled feature in actual build sources, not a profile name."""
    work = upstream / 'out/nabu'
    options = (work / '.config').read_text(encoding='utf-8').splitlines()
    if 'CONFIG_XNU_OWNER_DATA_MOUNT=y' not in options:
        return None
    if not prepared:
        raise ValueError('Enabled Data mount has no skeleton preparation receipt')
    if prepared.get('after_sha256') != hashlib.sha256(skeleton_patch()).hexdigest():
        raise ValueError('Data skeleton preparation does not match the current source')
    source = work / 'tree/.cache/xnu-work/bsd/kern/kern_exec.c'
    text = source.read_text(encoding='utf-8')
    call = '\tif (!error) error = native_owner_data_skeleton(p, scratch, data_mount);\n'
    # The recorder inserts this observer between the helper and stage publication.
    # Select the exact sequence from the build mode, not arbitrary intervening code.
    if capture_logs:
        call += '\tnabu_data_mount_progress(5, error);\n'
    call += '\tif (!error) native_owner_data_stage = 4;'
    if text.count(helper_source().rstrip()) != 1 or text.count(call) != 1:
        raise ValueError('Actual kern_exec.c lacks the complete Data skeleton or its stage-4 call')
    return {'source': 'outputs/tree/.cache/xnu-work/bsd/kern/kern_exec.c',
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'patch_sha256': prepared['after_sha256'],
            'directory_count': len(DIRECTORIES), 'symlink_count': len(SYMLINKS),
            'capture_stage5_observer': capture_logs,
            'runtime_qualified': False}
