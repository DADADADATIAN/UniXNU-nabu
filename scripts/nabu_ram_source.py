"""Compile out the optional UFS store when RAM Data is explicitly volatile."""


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('NativeRamBlock persistence source drift: ' + old[:90])
    return text.replace(old, new, 1)


def close_brace(text, opening):
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i + 1
    raise ValueError('Unbalanced pinned NativeRamBlock source')


def guard_block(text, anchor, body_only=False):
    if text.count(anchor) != 1:
        raise ValueError('NativeRamBlock block drift: ' + anchor)
    start = text.index(anchor)
    opening = text.index('{', start)
    end = close_brace(text, opening)
    if body_only:
        return text[:opening + 1] + '\n#if NABU_RAM_PERSISTENCE\n' + text[opening + 1:end - 1] + '\n#endif\n' + text[end - 1:]
    if text[end:end + 1] == ';':
        end += 1
    return text[:start] + '\n#if NABU_RAM_PERSISTENCE\n' + text[start:end] + '\n#endif\n' + text[end:]


def volatile_source(text):
    marker = '/* NABU_RAM_VOLATILE_V1: no physical persistence imports */'
    if marker in text:
        return text
    prefix = (marker + '\n#ifndef NABU_RAM_PERSISTENCE\n'
              '#define NABU_RAM_PERSISTENCE 1\n#endif\n')
    first = 'unsigned native_ufs_store_mode(void) __attribute__((weak_import));'
    last = 'unsigned native_ufs_store_gpt_check(void) __attribute__((weak_import));'
    text = once(text, first, '#if NABU_RAM_PERSISTENCE\n' + first)
    text = once(text, last, last + '\n#endif')
    text = guard_block(text, '  struct StoreOps {')
    text = guard_block(text, '  void attachStore() {', body_only=True)
    text = once(text, '    if(direct){\n', '#if NABU_RAM_PERSISTENCE\n    if(direct){\n')
    text = once(text, '    } else {\n    actual=ramSparseIO(',
                '    } else\n#endif\n    {\n    actual=ramSparseIO(')
    text = guard_block(text, '    if(!direct && write && actual==bytes && overlay.active && !overlay.readOnly){')
    return prefix + text
