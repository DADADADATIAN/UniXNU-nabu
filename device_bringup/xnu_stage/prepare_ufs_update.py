#!/usr/bin/env python3
"""Render the reviewed install/restore flow for a subsequent UFS candidate.

This module only returns a script. The caller must bind original files/menu,
fresh boot identity and both private CI artifacts before transport/execution.
"""
from pathlib import Path
import re

TEMPLATE = Path(__file__).with_name('ufs_readonly_stage.sh')
PINS = (
    '7f9f75e928bb3297e36eec04fceeb0d382c255a4aa15207cc1275c65c5bb3005',
    '08d226bcea2c03fb628bbfcea196ffc91accfed6be9dc5e0dc30dc6b9550d322',
    'ca3d6d432e4703ed5a9916a36f37344563ef879f1fee040a357fe23bd0739693',
)


def render_script(previous_run, next_run, kernel_sha256, adt_sha256, menu_sha256):
    if any(type(run) is not int or run <= 0 for run in (previous_run, next_run)) or previous_run == next_run:
        raise ValueError('Explicit distinct positive CI run IDs are required')
    hashes = (kernel_sha256, adt_sha256, menu_sha256)
    if not all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in hashes):
        raise ValueError('Expected exact SHA-256 pins')
    text = TEMPLATE.read_text(encoding='utf-8')
    old = 'OLD=Payloads/kernel-nabu-ufs-inspect.macho'
    new = 'NEW=Payloads/kernel-nabu-ufs-readonly-40134241308.macho'
    if text.count(old) != 1 or text.count(new) != 1 or text.count('ufs-readonly-40134241308-') != 2:
        raise ValueError('Reviewed UFS stage template drifted')
    text = text.replace(old, f'OLD=Payloads/kernel-nabu-ufs-readonly-{previous_run}.macho', 1)
    text = text.replace(new, f'NEW=Payloads/kernel-nabu-ufs-readonly-{next_run}.macho', 1)
    text = text.replace('ufs-readonly-40134241308-', f'ufs-readonly-{next_run}-')
    for before, after in zip(PINS, hashes):
        if text.count(before) != 1:
            raise ValueError('Reviewed UFS hash anchor drifted')
        text = text.replace(before, after, 1)
    return text.encode('utf-8')
