#!/usr/bin/env python3
"""Compute the original-kext closure for the staged 21H16 graphics roots.

This is a static audit: it reads the original kernelcache's __PRELINK_INFO and
never modifies the image.  When --native is supplied it also runs the pinned
NativePrelink planner against the pass-1 reference candidate, but a planner
failure is reported rather than hidden.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

# Keep these lists aligned with prepare_source.py.  The script stays standalone
# so it can run before a build tree exists.
DEFAULT_BASELINE_ROOTS = [
    'com.apple.filesystems.apfs',
    'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib',
    'com.apple.driver.AppleMobileFileIntegrity',
    'com.apple.security.sandbox',
]
DEFAULT_ROOTS = DEFAULT_BASELINE_ROOTS + [
    'com.apple.iokit.IOSurface',
    'com.apple.iokit.IOMobileGraphicsFamily',
]


def native_prelink_module(explicit):
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    root = Path(__file__).resolve().parents[4]
    candidates += [
        root / 'device_bringup/ipados17_inputs/tools/NativePrelink-3380d300',
        root / 'project_audit/unixnu-nabu-port-20261023/submodules/kits/NativePrelink',
    ]
    for candidate in candidates:
        if (candidate / 'native_prelink.py').is_file():
            sys.path.insert(0, str(candidate))
            import native_prelink
            commit = None
            if (candidate / '.git').exists():
                result = subprocess.run(
                    ['git', '-C', str(candidate), 'rev-parse', 'HEAD'],
                    capture_output=True, text=True)
                if result.returncode == 0:
                    commit = result.stdout.strip()
            return native_prelink, candidate, commit
    raise SystemExit('NativePrelink not found; pass --native-prelink')


def metadata_entries(native_prelink, data):
    image = native_prelink.macho(data)
    info = next((segment for segment in image['segments']
                 if segment['name'] == '__PRELINK_INFO'), None)
    if info is None:
        raise ValueError('Kernelcache has no __PRELINK_INFO segment')
    at = native_prelink.backed_offset(
        image['segments'], info['va'], info['filesize'], len(data))
    metadata = native_prelink.unserialize_xml(data[at:at + info['filesize']])
    entries = {}
    for entry in metadata['_PrelinkInfoDictionary']:
        identifier = entry['CFBundleIdentifier']
        if identifier in entries:
            raise ValueError(f'Duplicate prelink identifier: {identifier}')
        entries[identifier] = entry
    return entries


def closure(entries, roots):
    selected, interfaces = set(), set()
    pending = list(roots)
    while pending:
        identifier = pending.pop()
        if identifier in selected or identifier in interfaces:
            continue
        if identifier not in entries:
            raise ValueError(f'Missing declared dependency: {identifier}')
        entry = entries[identifier]
        if entry.get('OSKernelResource') is True:
            interfaces.add(identifier)
            continue
        selected.add(identifier)
        pending.extend(entry.get('OSBundleLibraries') or {})
    codeless = selected - {
        identifier for identifier in selected
        if entries[identifier].get('_PrelinkExecutableLoadAddr')
        and entries[identifier].get('_PrelinkExecutableSize')
    }
    for identifier in codeless:
        entry = entries[identifier]
        executable_keys = ('CFBundleExecutable', '_PrelinkExecutableLoadAddr',
                           '_PrelinkExecutableSourceAddr', '_PrelinkExecutableSize',
                           '_PrelinkKmodInfo')
        if (any(key in entry for key in executable_keys)
                or not isinstance(entry.get('IOKitPersonalities'), dict)
                or not entry['IOKitPersonalities']):
            raise ValueError('Codeless component is malformed: ' + identifier)
    return {
        'components': sorted(selected - codeless),
        'codeless_components': sorted(codeless),
        'kernel_interfaces': sorted(interfaces),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernelcache', required=True, type=Path)
    parser.add_argument('--native-prelink', type=Path)
    parser.add_argument('--native', type=Path,
                        help='pass-1 reference kernel.macho for a full plan')
    parser.add_argument('--slide', type=lambda value: int(value, 0),
                        default=-0x1360000)
    parser.add_argument('--root', action='append', default=None)
    parser.add_argument('--baseline-root', action='append', default=None)
    parser.add_argument('--expect-components', type=int)
    parser.add_argument('--expect-added', type=int)
    parser.add_argument('--forbid', action='append', default=[])
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()

    native_prelink, tool_dir, tool_commit = native_prelink_module(args.native_prelink)
    data = args.kernelcache.read_bytes()
    entries = metadata_entries(native_prelink, data)
    roots = args.root or DEFAULT_ROOTS
    baseline = args.baseline_root or DEFAULT_BASELINE_ROOTS
    result = closure(entries, roots)
    baseline_result = closure(entries, baseline)
    added = sorted(set(result['components']) - set(baseline_result['components']))
    removed = sorted(set(baseline_result['components']) - set(result['components']))
    counts = {
        'components': len(result['components']),
        'codeless_components': len(result['codeless_components']),
        'kernel_interfaces': len(result['kernel_interfaces']),
        'total': sum(len(result[key]) for key in
                     ('components', 'codeless_components', 'kernel_interfaces')),
        'added_vs_baseline': len(added),
    }
    forbidden_hits = sorted(set(args.forbid) & set(result['components']))
    plan = None
    plan_error = None
    if args.native is not None:
        try:
            plan = native_prelink.plan(
                args.native.read_bytes(), data, roots, args.slide)
            plan = {
                'native_sha256': plan['native_sha256'],
                'components': plan['components'],
                'codeless_components': plan['codeless_components'],
                'kernel_interfaces': plan['kernel_interfaces'],
                'pointer_counts': plan['pointer_counts'],
                'loadable': plan['loadable'],
                'abi_qualified': plan['abi_qualified'],
                'instruction_relocation_complete': plan['instruction_relocation_complete'],
            }
        except (KeyError, ValueError, OSError) as error:
            plan_error = str(error)

    report = {
        'kernelcache': str(args.kernelcache.resolve()),
        'kernelcache_sha256': hashlib.sha256(data).hexdigest(),
        'native_prelink': {
            'path': str(tool_dir.resolve()),
            'commit': tool_commit,
        },
        'roots': roots,
        'baseline_roots': baseline,
        **result,
        'added_vs_baseline': added,
        'removed_vs_baseline': removed,
        'forbidden': sorted(args.forbid),
        'forbidden_hits': forbidden_hits,
        'counts': counts,
        'native_plan': plan,
        'native_plan_error': plan_error,
        'images_modified': False,
        'runtime_qualified': False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    print(json.dumps({
        'components': counts['components'],
        'codeless_components': counts['codeless_components'],
        'kernel_interfaces': counts['kernel_interfaces'],
        'added_vs_baseline': counts['added_vs_baseline'],
        'added': added,
        'forbidden_hits': forbidden_hits,
        'native_plan': 'ok' if plan is not None else plan_error,
    }, indent=2))

    if forbidden_hits:
        raise SystemExit('Forbidden graphics components present: ' + ', '.join(forbidden_hits))
    if args.expect_components is not None and counts['components'] != args.expect_components:
        raise SystemExit(f"Expected {args.expect_components} components, got {counts['components']}")
    if args.expect_added is not None and counts['added_vs_baseline'] != args.expect_added:
        raise SystemExit(f"Expected {args.expect_added} added components, got {counts['added_vs_baseline']}")


if __name__ == '__main__':
    main()