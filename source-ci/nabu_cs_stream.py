"""Keep full native-signature authentication scans out of the vnode page cache."""
import hashlib
from pathlib import Path
import struct

PATCH = 'patches/xnu/native-4k-signature-hash-cache.patch'
PINNED_SHA256 = 'f9a8b4d39022a726ba1e0e4842248d57b20fe3a05fbf41b3a01f6700b2e3ca72'
ORIGINAL = ('+\t\terror = vn_rdwr(UIO_READ, vp, (caddr_t)buffer, (int)length, position,\n'
            '+\t\t    UIO_SYSSPACE, 0, vfs_context_ucred(vfs_context_current()),\n'
            '+\t\t    &resid, current_proc());')
STREAMING = ORIGINAL.replace('UIO_SYSSPACE, 0,', 'UIO_SYSSPACE, IO_NOCACHE | IO_RAOFF,')
ANCHOR = 'static int\ncs_native4k_prepare(vnode_t vp, struct cs_blob *blob)\n{'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def streaming_patch(original):
    if digest(original) != PINNED_SHA256:
        raise ValueError('Native signature patch differs from the pinned authentication implementation')
    text = original.decode('utf-8')
    if text.count(ORIGINAL) != 1:
        raise ValueError('Expected exactly one full-authentication scan read')
    return text.replace(ORIGINAL, STREAMING, 1).encode('utf-8')


def prepare_signature_scan(upstream):
    path = upstream / PATCH
    before = path.read_bytes()
    after = streaming_patch(before)
    path.write_bytes(after)
    return {'patch': PATCH, 'before_sha256': digest(before), 'after_sha256': digest(after),
            'read_flags': ['IO_NOCACHE', 'IO_RAOFF'],
            'full_authentication_preserved': True, 'runtime_qualified': False}


def function_body(text):
    if text.count(ANCHOR) != 1:
        raise ValueError('Expected the actual native signature authenticator exactly once')
    start = text.index(ANCHOR)
    opening = start + len(ANCHOR) - 1
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == '{':
            depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise ValueError('Unbalanced native authenticator body')


def expected_body(patch):
    additions = '\n'.join(line[1:] for line in patch.decode().splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
    return function_body(additions)


def defined_symbols(data):
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise ValueError('Expected the actual ordinary ARM64 authentication object')
    at, table = 32, None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        if command == 2:
            table = struct.unpack_from('<4I', data, at + 8)
        at += size
    if table is None:
        raise ValueError('Authentication object lacks its symbol table')
    symoff, count, stroff, _ = table
    result = set()
    for index in range(count):
        string, kind, _, _, _ = struct.unpack_from('<IBBHQ', data, symoff + index * 16)
        if string and (kind & 0xe) == 0xe:
            result.add(data[stroff + string:data.index(b'\0', stroff + string)].decode())
    return result


def qualify_signature_scan(upstream, prepared):
    work = upstream / 'out/nabu'
    if 'CONFIG_XNU_NATIVE_CS_HASH_CACHE=y' not in (work / '.config').read_text().splitlines():
        return None
    if not prepared or prepared.get('patch') != PATCH or prepared.get('before_sha256') != PINNED_SHA256:
        raise ValueError('Enabled signature scan has no pinned preparation receipt')
    tree = work / 'tree'
    patch = (tree / PATCH).read_bytes()
    if (digest(patch) != prepared.get('after_sha256') or
            prepared.get('read_flags') != ['IO_NOCACHE', 'IO_RAOFF'] or
            prepared.get('full_authentication_preserved') is not True):
        raise ValueError('Signature scan IO preparation changed')
    # Reversing only the flags must recover every byte of the fixed upstream patch.
    if patch.count(STREAMING.encode()) != 1:
        raise ValueError('Signature scan flags are missing or duplicated')
    original = patch.replace(STREAMING.encode(), ORIGINAL.encode(), 1)
    if digest(original) != PINNED_SHA256:
        raise ValueError('Signature authentication changed beyond the scan IO policy')
    source = tree / '.cache/xnu-work/bsd/kern/ubc_subr.c'
    text = source.read_text()
    if function_body(text) != expected_body(patch):
        raise ValueError('Actual signature authenticator differs from the complete qualified body')
    call = '\terror = cs_native4k_prepare(vp, &tmp_blob);\n\tif (error != 0) {\n\t\tgoto out;\n\t}'
    if text.count(call) != 1:
        raise ValueError('Authentication errors are not rejected before blob publication')
    obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/ubc_subr.o'
    raw = obj.read_bytes()
    required = {'_cs_native4k_prepare', '_cs_native4k_hash_cache_version',
                '_cs_native4k_full_blocks', '_cs_native4k_ready_blobs', '_cs_native4k_page_checks'}
    if not required <= defined_symbols(raw):
        raise ValueError('Native signature authenticator was not compiled into its actual object')
    return {'source': 'outputs/tree/.cache/xnu-work/bsd/kern/ubc_subr.c',
            'source_sha256': digest(source.read_bytes()),
            'object': 'outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/ubc_subr.o',
            'object_sha256': digest(raw), 'patch_sha256': digest(patch),
            'read_flags': prepared['read_flags'], 'complete_function_body_verified': True,
            'full_authentication_preserved': True, 'runtime_qualified': False}
