"""Select Apple's real ARM I/O class for explicitly requested QEMU nubs."""

FACTORY = '''static IOService *createOriginalArmIONub (IORegistryEntry *entry)
{
  OSObject *object = OSMetaClass::allocClassWithName ("AppleARMIODevice");
  IOService *nub = OSDynamicCast (IOService, object);
  // The cast borrows the factory reference; release it only once.
  if (nub == nullptr || !nub->init (entry, gIODTPlane)) {
    if (object != nullptr) { object->release (); }
    return nullptr;
  }
  return nub;
}

'''

NUB = '''    if (entry->getProperty ("armdt,nabu-boot-pmgr") != nullptr) {
      if (!nabu_boot_pmgr_publish (this, entry)) {
        iterator->release ();
        return false;
      }
      // Optional: needs wdt=-1 and logs why when not published; boot continues.
      nabu_watchdog_publish (this);
      // Optional: needs nabu-touch=1; starts its own worker and never blocks boot.
      nabu_touch_publish (this);
      count++;
      continue;
    }
    if (entry->getProperty ("armdt,qemu-boot-pmgr") != nullptr) {
      if (!qemu_boot_pmgr_publish (this, entry)) {
        iterator->release ();
        return false;
      }
      count++;
      continue;
    }
    bool originalArmIO = entry->getProperty ("armdt,apple-arm-io") != nullptr;
    IOService *nub = originalArmIO ? createOriginalArmIONub (entry) : createNub (entry);
    if (nub == nullptr) {
      if (originalArmIO) {
        IOLog ("ArmDTPlatform: original AppleARMIODevice allocation/init failed\\n");
        iterator->release ();
        return false;
      }
      continue;
    }
    if (!nub->attach (this)) {
      nub->release ();
      if (originalArmIO) {
        IOLog ("ArmDTPlatform: original AppleARMIODevice attach failed\\n");
        iterator->release ();
        return false;
      }
      continue;
    }
    if (originalArmIO) {
      armdt_platform_original_armio_registry_id = nub->getRegistryEntryID ();
      IOLog ("ArmDTPlatform: registering %s registry-id=%llu\\n",
             nub->getMetaClass ()->getClassName (),
             (unsigned long long)armdt_platform_original_armio_registry_id);
    }
'''


def patch_source(text):
    start = '    IOService *nub = createNub (entry);\n'
    end = '    nub->registerService ();\n'
    method = 'bool ArmDTPlatform::createDeviceNubs (IOService *provider)\n'
    if text.count(start) != 1 or text.count(method) != 1:
        raise ValueError('Expected the pinned ArmDTPlatform bus-nub creation path')
    first = text.index(start)
    last = text.index(end, first)
    text = text[:first] + NUB + text[last:]
    text = text.replace(method, FACTORY + method, 1)
    return text.replace('extern "C" {\n',
                        'extern "C" {\n'
                        '__attribute__((weak)) bool qemu_boot_pmgr_publish (IOService *, IORegistryEntry *);\n'
                        '__attribute__((weak)) bool nabu_boot_pmgr_publish (IOService *, IORegistryEntry *);\n'
                        '__attribute__((weak)) bool nabu_watchdog_publish (IOService *);\n'
                        '__attribute__((weak)) bool nabu_touch_publish (IOService *);\n'
                        'volatile uint64_t armdt_platform_original_armio_registry_id = 0;\n', 1)
