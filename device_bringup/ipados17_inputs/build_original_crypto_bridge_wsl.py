#!/usr/bin/env python3
"""Build an isolated PRNG bootstrap variant for original prelinked CoreCrypto.

The explicit boot argument selects the original, already initialized PRNG; it
refuses to proceed if that PRNG is absent. The source provider's status remains
KERN_NOT_SUPPORTED in this mode, never a fabricated success. Both POST paths,
the PRNG assertion and all existing device candidates remain unchanged.
"""
import difflib
import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOT = Path('/tmp/hackios-batch-build-20261022')
OLD = '/Users/chuzu/Desktop/UniXNU-build/unixnu-mac-offline-20261021/work/UniXNU'
OBJROOT = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
SOURCE = ROOT / '.cache/xnu-work/osfmk/prng/prng_random.c'
OUT = REPO / 'device_bringup/ipados17_inputs/system-17.7-21H16-20261023/crypto-bridge'


def run(command, cwd, log):
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    log.write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.stdout[-9000:])
    return result


def main():
    OUT.mkdir(exist_ok=False)
    base = SOURCE.read_text()
    if 'source_corecrypto14_bootstrap' in base:
        raise ValueError('requires the restored unmodified PRNG source')
    patch = (REPO / 'mac_build/evidence/mac-current-20261022/patches/xnu/source-corecrypto14-bootstrap.patch').read_text()
    addition = '\n'.join(line[1:] for line in patch.splitlines()
                         if line.startswith('+') and not line.startswith('+++')) + '\n'
    anchor = '\tuint32_t mode = 0;\n'
    if addition.count(anchor) != 1:
        raise ValueError('ambiguous source-provider insertion anchor')
    selection = '''
\t/* Original prelinked provider initializes before EARLY_BOOT. */
\tif (PE_parse_boot_argn("hackios-original-crypto", &mode, sizeof(mode)) && mode == 1) {
\t\tif (!prng_ready) {
\t\t\tpanic("selected original CoreCrypto has not initialized the PRNG");
\t\t}
\t\tsource_corecrypto14_status = KERN_NOT_SUPPORTED;
\t\treturn;
\t}
\tmode = 0;
'''
    original = base + addition
    source = base + addition.replace(anchor, anchor + selection)
    destination = OUT / 'prng_random-original-crypto.c'
    destination.write_text(source)
    (OUT / 'provider-selection.diff').write_text(''.join(difflib.unified_diff(
        original.splitlines(True), source.splitlines(True),
        fromfile='prng_random.c+source-bootstrap', tofile=destination.name)))
    record = json.JSONDecoder().raw_decode((OBJROOT / 'osfmk/DEVELOPMENT/prng_random.o.json').read_text())[0]
    raw = [value.replace(OLD, str(ROOT)) for value in record['arguments']]
    args, removed, i = [], [], 0
    while i < len(raw):
        value = raw[i]
        if value == '-Xclang' and i + 1 < len(raw) and (
            raw[i + 1].startswith('-clang-vendor-feature=') or raw[i + 1] == '-fno-odr-hash-protocols'):
            removed.extend(raw[i:i + 2]); i += 2; continue
        if value.startswith('-mlinker-version='):
            removed.append(value); i += 1; continue
        args.append(value); i += 1
    args[0] = '/usr/bin/clang-21'
    source_index = args.index(str(SOURCE))
    args[source_index] = str(destination)
    obj = OUT / 'prng_random-original-crypto.o'
    args[args.index('-o') + 1] = str(obj)
    args += ['-mgeneral-regs-only']
    (OUT / 'compile-command.json').write_text(json.dumps(dict(arguments=args, removed=removed), indent=2) + '\n')
    run(args, OBJROOT / 'osfmk/DEVELOPMENT', OUT / 'compile.log')
    report = json.loads((REPO / 'device_bringup/batch_diagnostics/build/batch-build-report.json').read_text())
    link = list(report['link_command'])
    kernel = OUT / 'kernel-nabu-original-crypto-base.macho'
    link[link.index('--output') + 1] = str(kernel)
    if any(value.startswith('osfmk/DEVELOPMENT/prng_random.o=') for value in link):
        raise ValueError('base command already replaces PRNG object')
    link += ['--replace-object', 'osfmk/DEVELOPMENT/prng_random.o=' + str(obj)]
    (OUT / 'link-command.json').write_text(json.dumps(link, indent=2) + '\n')
    run(link, ROOT, OUT / 'link.log')
    nm = '/tmp/hackios-relink-20261022/cctools-install/bin/arm64-apple-darwin-nm'
    undefined = run([nm, '-u', str(kernel)], ROOT, OUT / 'undefined.txt').stdout.strip()
    if undefined:
        raise ValueError('undefined symbols: ' + undefined)
    run(['python3', str(REPO / 'mac_build/evidence/mac-current-20261022/scripts/seal-source-crypto-kernel.py'),
         str(kernel)], ROOT, OUT / 'seal.log')
    (OUT / 'build-report.json').write_text(json.dumps(dict(kernel=str(kernel),
        boot_argument='hackios-original-crypto=1', original_source_modified=False,
        undefined_symbol_count=0, hardware_tested=False, runtime_verified=False), indent=2) + '\n')
    print(kernel)


if __name__ == '__main__':
    main()
