"""Selected 21H16 CPU presentation contracts, bound to audited original bytes."""
import hashlib

ACTIVE_REQUEST = 0xfffffff005cccd78
DISPLAY_STATE = 0xfffffff005cda0cc
WINDOWS = (
    ('firmware_powered_setter', DISPLAY_STATE, 512, 'b462d64a7de48c4af1d750aec6ebab3f4d7403a43b9115aa9ee28b3563c5c9e8'),
    ('kick_default', 0xfffffff005cd7030, 16, 'd53e8c59aa22c23dbfc99dd98e5e02cf4ba052a2905b2991bfe1edff9c0b9efa'),
    ('complete_wrapper', 0xfffffff005cd8b88, 44, '58824b8b6fdd7a92e87bfbfaaa3a354309489ac33ace6420111c235595846121'),
    ('validate_default', 0xfffffff005cd8bb4, 28, '124fe177efe1b0265836df52b214ee662c5f4ca2a0f70dc1683426c15a56e3f9'),
    ('validate_dispatch', 0xfffffff005cd3e9c, 68, 'e06c1eadda373a306fbdab664aa4f3f18837da711863ce47404fb4e9cd3a57e5'),
    ('dequeue_activate', 0xfffffff005ccd80c, 144, '57c848adf80f232053433f0f7ec4df87521e4b97e87923dd259650cf4a496231'),
    ('rect_construct', 0xfffffff005cd2ad4, 144, 'a10a46299291443cd8a7e7571c105814f2d076ec671ee02abea4e6861f730470'),
    ('rect_current_a', 0xfffffff005ce14d0, 28, '9bce09a8a0d62e25fa74f783be2e27e01781798f19e7f11280c1b7454774447f'),
    ('rect_current_b', 0xfffffff005ce1570, 28, '301a4be1f8435bf39b73c895c02d79886e963ea36012872f70795c70fd9d2845'),
    ('request_active_entry', ACTIVE_REQUEST, 36, '046983d812dac9085e57b1dfb49b7745a2f7080fc8df66e961db5a9020fe9bb5'),
    ('request_size_write', 0xfffffff005cd25c0, 48, 'f17003576285d11f6eb0edeb5886d9826f8c9c6bd5f2446ca5baa6962a29693c'),
)


def qualify(read, methods):
    if any(methods[slot] != va for slot, va in (
            (290, 0xfffffff005cd7030), (295, 0xfffffff005cd8b88), (296, 0xfffffff005cd8bb4))):
        raise ValueError('CPU presentation extension-point targets changed')
    windows = []
    for name, va, size, digest in WINDOWS:
        code = read(va, size)
        if len(code) != size or hashlib.sha256(code).hexdigest() != digest:
            raise ValueError('CPU presentation original instruction mismatch: ' + name)
        windows.append(dict(name=name, raw_va=hex(va), bytes=size, sha256=digest))
    return {
        'status': 'static_qualified', 'scope': 'single full-frame uncompressed BGRA or explicit black blank',
        'windows': windows, 'display_queue': {'current': 5472, 'head': 5480, 'tail': 5488},
        'request': {'next': 2960, 'previous': 2968, 'surface_array': 2624,
                    'updated': 792, 'disabled': 796, 'background': 800,
                    'width': 816, 'height': 820, 'rectangles': [17, 81]},
        'opaque_words_required_zero': [804, 808, 812],
        'opaque_words_semantics': 'unsupported nonzero values rejected; not classified as generic options',
        'activation_notification': {'raw_va': hex(ACTIVE_REQUEST), 'arguments': 'this, request, uint32 mode=3'},
        'completion': {'slot': 295, 'arguments': 'this; original wrapper passes force=1'},
        'logical_schedule_state': {'slot': 354, 'raw_va': hex(DISPLAY_STATE),
                                   'requested_word': 5836, 'requested_value': 1,
                                   'powered_word': 5840, 'powered_claimed': True,
                                   'meaning': 'original swap entry requires +5836 != 0 (UniXNU logical PM); '
                                              '+5840=1 records the firmware-lit GOP panel as UniXNU '
                                              'announcePoweredByFirmware does; not hardware PM'},
        'console_handoff': 'standard PE_initialize_console(kPEDisableScreen), explicit CPU profile only',
        'runtime_qualified': False, 'user_client_contract': 'unknown',
        'limitation': 'Static limited backend contract; actual producer, queue serialization and completion need execution evidence',
    }
