"""Original 21H16 IOStorageFamily bindings shared by all nabu block transports.

The addresses come from the same prepared kernelcache as the owner-root
candidate.  Only one archive may provide these absolute aliases; NativeRamBlock
is linked as a plain object beside the VirtIO binding provider.
"""

BINDINGS = {
    '__ZTV20IOBlockStorageDevice': 0xfffffff0059644c0,
    '__ZN20IOBlockStorageDevice10gMetaClassE': 0xfffffff0067751d0,
    '__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass': 0xfffffff0046ced98,
    '__ZN20IOBlockStorageDeviceD2Ev': 0xfffffff0046cedb8,
    '__ZN20IOBlockStorageDevice4initEP12OSDictionary': 0xfffffff0046cee30,
    '__ZNK20IOBlockStorageDevice11getPropertyEPK8OSSymbol': 0xfffffff0046cee88,
    '__ZN20IOBlockStorageDevice13setPropertiesEP8OSObject': 0xfffffff0046cef38,
    '__ZN20IOBlockStorageDevice11requestIdleEv': 0xfffffff0046cf050,
    '__ZN20IOBlockStorageDevice7doUnmapEP26IOBlockStorageDeviceExtentjj': 0xfffffff0046cf05c,
    '__ZN20IOBlockStorageDevice13doSetPriorityEP26IOBlockStorageDeviceExtentjh': 0xfffffff0046cf068,
    '__ZN20IOBlockStorageDevice20doGetProvisionStatusEyyPjP35IOBlockStorageProvisionDeviceExtenty': 0xfffffff0046cf08c,
}