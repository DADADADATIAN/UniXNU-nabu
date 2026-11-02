#!/usr/bin/env python3
"""Build the opt-in SM8150/A640 CP proof archive from preserved licensed sources.

NABU_GPU_METAL=1 additionally compiles the publication path, defers the two
objects whose static initializers may only run after the original IOGPUFamily has
registered, and links the original-base bindings. The bindings are derived by
nabu-device/scripts/nabu_adreno_bindings.py from a candidate prelink report; when
no such report is supplied the builder records predicted addresses and the CI
qualifier refuses the candidate, which is what makes the first metal run a probe
that yields the report the second run needs.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

CPP = (
    'NativeAdrenoMemory', 'NativeAdrenoVm', 'NativeAdrenoCpu', 'NativeAdrenoKernelTime',
    'NativeAdrenoRing', 'NativeAdrenoCpInit', 'NativeAdrenoIrq', 'NativeAdrenoSmmuMemory',
    'NativeAdrenoSmmuContext', 'NativeAdrenoGmuMemory', 'NativeAdrenoGmuContext',
    'NativeAdrenoGpuContext', 'NativeAdrenoA6xxPower', 'NativeAdrenoA6xxGmu',
    'NativeAdrenoA6xxHwInit', 'NativeAdrenoA6xxSmmu', 'NativeAdrenoA6xxZap',
    'NativeAdrenoService', 'NativeAdrenoSha256', 'NativeAdrenoGpuProfile', 'NabuGpuResources',
)
# Publication path. NativeAdrenoTimer is required: NativeAdrenoUserClient reads the
# always-on counter through it, so dropping it leaves a link gap.
METAL_CPP = (
    'NativeAdrenoSubmit', 'NativeAdrenoTimer', 'NativeAdrenoUserClient', 'NativeAdrenoClient',
    'NativeAdrenoPublish', 'NativeAdrenoAccelerator', 'NativeAdrenoScheduler',
)
# Exactly these two defer their static initializer; their __text must not change.
LATE_CPP = ('NativeAdrenoPublish', 'NativeAdrenoAccelerator')
BINDINGS_SCRIPT = 'scripts/nabu_adreno_bindings.py'
BINDINGS_FILE = 'original-accelerator-bindings.S'
BINDINGS_OBJECT = 'original-accelerator-bindings.o'
BINDINGS_REPORT = 'adreno-bindings.json'
BINDING_SYMBOLS = ('__ZN15IOAcceleratorESC2EPK11OSMetaClass',
                   '__ZN15IOAcceleratorESD2Ev',
                   '__ZN15IOAcceleratorES10gMetaClassE')
SAFE_SUFFIXES = {'.cpp', '.c', '.h', '.json'}
SAFE_NAMES = {'LICENSE', 'COPYING', 'PROVENANCE'}
PROFILE = 'nabu_ufs_gpu_metal_defconfig'
DIAGNOSTIC_PROFILE = 'nabu_ufs_gpu_defconfig'
KERNELCACHE_SHA256 = 'f7d1952c7a21633d212eccf288e77444fff0cc86976db5de292f6819c2ffa1b2'
SLIDE = -0x1360000
ADDRESS = re.compile('0x[0-9a-f]{16}')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha(path.read_bytes())


def source_inventory(device, metal=False):
    gpu = device / 'gpu'
    paths = sorted(p for p in gpu.rglob('*') if p.is_file() and
                   (p.suffix in SAFE_SUFFIXES or p.name in SAFE_NAMES))
    paths.append(device / 'scripts/build-nabu-adreno.py')
    if metal:
        paths.append(device / BINDINGS_SCRIPT)
    if any(p.is_symlink() for p in paths):
        raise ValueError('GPU source cannot be a symlink')
    return {p.relative_to(device).as_posix(): sha(p.read_bytes()) for p in paths}


def source_identity(sources):
    return sha(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())


def verify_pmap(data):
    text = data.decode('utf-8')
    match = re.search(r'\bpmap_sync_page_attributes_phys\s*\([^)]*\)\s*\{([^}]+)\}', text)
    if not match or not re.search(r'flush_dcache\s*\(\s*\(vm_offset_t\)\s*ptoa\(pp\)', match[1]):
        raise ValueError('GPU NC allocation requires the applied pmap >=4 GiB physical address fix')
    if re.search(r'pp\s*<<\s*PAGE_SHIFT', re.sub(r'/\*.*?\*/', '', match[1], flags=re.S)):
        raise ValueError('pmap physical page shift still truncates above 4 GiB')


def text_bytes(path):
    """Return the bytes of the object's __text section."""
    data = path.read_bytes()
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise ValueError('Not an ARM64 object: ' + path.name)
    count = struct.unpack_from('<I', data, 16)[0]
    at = 32
    for _ in range(count):
        if at + 8 > len(data):
            break
        command, size = struct.unpack_from('<II', data, at)
        if command == 0x19:
            sections = struct.unpack_from('<I', data, at + 64)[0]
            for index in range(sections):
                section = at + 72 + 80 * index
                if section + 80 > len(data):
                    break
                if data[section:section + 16].rstrip(b'\0') != b'__text':
                    continue
                # section_64: size is the u64 at +40, offset the u32 at +48.
                extent = struct.unpack_from('<Q', data, section + 40)[0]
                offset = struct.unpack_from('<I', data, section + 48)[0]
                if not extent or offset + extent > len(data):
                    raise ValueError('Truncated __text in ' + path.name)
                return data[offset:offset + extent]
        at += size
    raise ValueError('No __text section in ' + path.name)


def predicted_bindings(kernelcache):
    """Bind the audited original addresses through the declared slide.

    This is a prediction, not a derivation: it is correct only while the module's
    segments keep their original offsets inside the candidate. The CI qualifier
    refuses a candidate built this way, so the prediction can never be installed
    as a verified result. It exists so the first metal run still produces the
    candidate report that the second run derives from.
    """
    abi = json.loads((Path(__file__).resolve().parents[1] /
                      'gpu/a640/ioaccelerator-base-abi.json').read_text(encoding='utf-8'))
    recorded = {
        BINDING_SYMBOLS[0]: abi['protected_compatible_constructor_aliases'][0],
        BINDING_SYMBOLS[1]: abi['nondeleting_destructor'],
        BINDING_SYMBOLS[2]: abi['metaclass'],
    }
    return {name: hex(int(address, 16) + SLIDE) for name, address in recorded.items()}


def main():
    if sys.platform != 'darwin':
        raise SystemExit('Apple archive compilation runs in the macOS GitHub Actions workflow')
    metal = os.environ.get('NABU_GPU_METAL') == '1'
    userprobe = os.environ.get('NABU_GPU_USERPROBE') == '1'
    if userprobe and not metal:
        raise SystemExit('GPU userprobe boot support is not part of the diagnostic profile')
    for name in ('XNU_NATIVE_ADRENO', 'XNU_NATIVE_UFS', 'XNU_OWNER_ROOT_TRUST', 'NABU_CAPTURE_LOG'):
        if os.environ.get(name) != '1':
            raise SystemExit('A640 diagnostic requires ' + name + '=1')
    root = Path(__file__).resolve().parents[1]
    device = Path(os.environ['UNIXNU_DEVICE']).resolve()
    config = (root.parent / '.config').read_text().splitlines()
    if 'CONFIG_XNU_NATIVE_ADRENO=y' not in config or 'CONFIG_XNU_NATIVE_MOBILE_DISPLAY=n' not in config:
        raise SystemExit('Unexpected A640 profile dependencies')
    out = root / 'build/native-adreno'
    if out.exists():
        raise SystemExit('Refuse existing GPU output; use a fresh build tree')
    pmap = root / '.cache/xnu-work/osfmk/arm/pmap/pmap.c'
    pmap_bytes = pmap.read_bytes()
    verify_pmap(pmap_bytes)
    kernelcache = Path(os.environ.get('UNIXNU_KERNELCACHE', ''))
    if not kernelcache.is_file():
        raise SystemExit('The selected kernelcache is required for the GPU identity')
    kernelcache_sha = sha256_file(kernelcache)
    if kernelcache_sha != KERNELCACHE_SHA256:
        raise SystemExit('GPU build requires the audited 21H16 kernelcache')
    sources = source_inventory(device, metal=metal)
    identity = source_identity(sources)
    staged = out / 'source'
    staged.mkdir(parents=True)
    # Merge first: quoted includes must resolve to the overlay header, rather
    # than an upstream header living beside an upstream translation unit.
    for directory in ('upstream/Adreno6xx', 'upstream/ArmSmmu4K', 'upstream/AdrenoPM4', 'a640', 'nabu'):
        for path in sorted((device / 'gpu' / directory).iterdir()):
            if path.is_file() and path.suffix in SAFE_SUFFIXES:
                shutil.copyfile(path, staged / path.name)
    (staged / 'NabuGpuBuild.h').write_text('#define NABU_GPU_SOURCE_ID "' + identity + '"\n', encoding='utf-8')
    logging_headers = {}
    for name in ('NabuLogCore.h', 'NabuLogFormat.h'):
        path = device / 'ufs' / name
        logging_headers[path.relative_to(device).as_posix()] = sha(path.read_bytes())
        shutil.copyfile(path, staged / name)
    spec = importlib.util.spec_from_file_location('nabu_platform_build', Path(__file__).with_name('build-nabu-platform.py'))
    platform = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(platform)
    base = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    recipes = {'cpp': base / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json',
               'c': base / 'bsd/DEVELOPMENT/bsd_init.o.json'}
    raw = {key: path.read_bytes() for key, path in recipes.items()}
    records = {key: json.loads(data.decode().strip().rstrip(',')) for key, data in raw.items()}
    c_sources = sorted(p.name for p in (device / 'gpu/upstream/ArmSmmu4K').glob('*.c'))
    c_sources += ['AdrenoPM4.c', 'NabuGpuStart.c']
    units = [(name + '.cpp', 'cpp') for name in (CPP + METAL_CPP if metal else CPP)]
    units += [(name, 'c') for name in c_sources]
    objects, commands, reports = [], {}, {}
    for name, language in units:
        source = staged / name
        obj = out / (source.stem + '.o')
        record = records[language]
        command = platform.compile_command(record, source, obj)
        command += ['-I', str(staged), '-I', str(root / '.cache/xnu-work/osfmk')]
        if metal:
            # Selects the publication path in the A640 overlay. The diagnostic
            # archive must not compile it, because it links none of those objects.
            command.append('-DNABU_GPU_METAL=1')
        result = subprocess.run(command, cwd=record['directory'], capture_output=True)
        (out / (source.stem + '.log')).write_bytes(result.stdout + result.stderr)
        commands[source.stem] = command
        (out / 'compile-command.json').write_text(json.dumps(commands, indent=2) + '\n')
        if any(recipes[key].read_bytes() != data for key, data in raw.items()):
            raise SystemExit('GPU build modified an original XNU compile record')
        if result.returncode:
            raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-6000:])
        platform.check_object(obj.read_bytes())
        record_out = {'source': 'source/' + name, 'source_sha256': sha(source.read_bytes()),
                      'object': obj.name, 'sha256': sha(obj.read_bytes())}
        if metal and source.stem in LATE_CPP:
            # Deferring the initializer is a reordering, not a rebuild: the text
            # must be byte-identical or the deferral changed the code.
            late = out / (source.stem + '.late.o')
            subprocess.run(['llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                            '--globalize-symbol=__GLOBAL__sub_I_' + name, str(obj), str(late)],
                           check=True)
            platform.check_object(late.read_bytes())
            plain_text, late_text = text_bytes(obj), text_bytes(late)
            if plain_text != late_text:
                raise SystemExit('Deferred object changed its text: ' + source.stem)
            record_out.update(object=late.name, kind='late', init_section_removed=True,
                              text_sha256=sha(plain_text), late_text_sha256=sha(late_text),
                              sha256=sha(late.read_bytes()))
            objects.append(late)
        else:
            objects.append(obj)
        reports[source.stem] = record_out
    bindings = None
    if metal:
        # The archive must exist before the kernel links, so the first build can
        # only predict the addresses through the declared slide. The CI qualifier
        # re-derives them from the finished candidate and refuses the candidate
        # unless the two agree, so a prediction can never be installed as verified.
        layout = os.environ.get('NABU_GPU_BINDINGS_LAYOUT', '')
        generator = device / BINDINGS_SCRIPT
        command = [sys.executable, '-B', str(generator),
                   '--kernelcache', str(kernelcache),
                   '--abi', str(device / 'gpu/a640/ioaccelerator-base-abi.json'),
                   '--slide', str(SLIDE),
                   '--output-dir', str(out)]
        if layout:
            command += ['--candidate', str(Path(layout).with_suffix('.macho')),
                        '--report', layout]
        else:
            command.append('--predict')
        result = subprocess.run(command, capture_output=True)
        (out / 'bindings-generator.log').write_bytes(result.stdout + result.stderr)
        plan = json.loads((out / BINDINGS_REPORT).read_text(encoding='utf-8'))
        if result.returncode or plan.get('status') != 'ok':
            raise SystemExit('Accelerator bindings were not derived from this candidate: ' +
                             str(plan.get('error') or result.stderr.decode('utf-8', 'replace')[-2000:]))
        binding = out / BINDINGS_OBJECT
        subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                        str(out / BINDINGS_FILE), '-o', str(binding)], check=True)
        platform.check_object(binding.read_bytes())
        objects.append(binding)
        bindings = {'source': BINDINGS_FILE, 'object': BINDINGS_OBJECT,
                    'source_sha256': sha256_file(out / BINDINGS_FILE),
                    'object_sha256': sha(binding.read_bytes()),
                    'report': BINDINGS_REPORT, 'report_sha256': sha256_file(out / BINDINGS_REPORT),
                    'scope': plan['bindings_scope'], 'layout': layout,
                    'symbols': plan['bindings']}
    archive = out / 'libNativeAdreno.a'
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), *map(str, objects)], check=True)
    report = {'profile': PROFILE if metal else DIAGNOSTIC_PROFILE,
              'mode': 'a640_metal' if metal else 'a640_diagnostic',
              'firmware_mode': 'adt', 'source_identity': identity, 'sources': sources,
              'logging_headers': logging_headers, 'objects': reports,
              'archive_sha256': sha(archive.read_bytes()),
              'kernelcache': str(kernelcache), 'kernelcache_sha256': kernelcache_sha,
              'metal_accelerator': metal, 'runtime_qualified': False, 'hardware_tested': False,
              'gpu_userprobe_boot_support': userprobe,
              'requires_pmap_64bit': True, 'pmap_sync_64bit_verified': True,
              'pmap_source_sha256': sha(pmap_bytes), 'startup': 'EARLY_BOOT thread; wait IOBSD',
              'trigger': 'nabu-gpu=1', 'irq_mode': 'synchronous worker polling',
              'table_memory': 'Normal NC; non-cacheable SMMU walks',
              'bindings': bindings,
              'publication': ({'objects': list(METAL_CPP), 'deferred': list(LATE_CPP),
                               'publishes': 'NativeAdrenoGpuPublished + AGXAccelerator',
                               'userspace_plugin': 'not built by this profile',
                               'user_bo_path': 'not qualified'}
                              if metal else None),
              'recipe_sha256': {key: sha(data) for key, data in raw.items()}}
    (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('mode', 'source_identity', 'archive_sha256')}))


if __name__ == '__main__':
    main()
