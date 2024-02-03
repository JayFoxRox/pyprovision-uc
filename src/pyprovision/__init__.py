import math
import os
import time
from zipfile import ZipFile
import requests
import json
import sys
import plistlib
from io import BytesIO
import base64
import datetime
from ctypes import *

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from unicorn import *
from unicorn.arm64_const import *

enableCache = False

returnAddress = 0xDEAD0000
stackAddress = 0xF0000000
stackSize = 0x100000

mallocAddress = 0x60000000
mallocSize = 0x1000000

importAddress = 0xA0000000
importSize = 0x1000

#FIXME: Define pageSize

def debugPrint(message):
    if False:
        print(message)

def debugTrace(message):
    if False:
        print(message)

def hook_mem_invalid(uc, access, address, size, value, user_data):
    vm = user_data
    assert(vm.uc == uc)

    if access == UC_MEM_WRITE_UNMAPPED:
        debugPrint(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
        # return True to indicate we want to continue emulation
        #return False
    elif access == UC_MEM_FETCH_UNMAPPED:
        debugPrint(">>> Missing memory is being FETCH at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
    else:
        # return False to indicate we want to stop emulation
        #return False
        pass
    assert(False)


def hook_code(uc, address, size, user_data):
    vm = user_data
    assert(vm.uc == uc)

    debugPrint(">>> Tracing at 0x%X:" % (address), end="")
    # read this instruction code from memory
    tmp = uc.mem_read(address, size)
    for i in tmp:
        debugPrint(" %02X" %i, end="")
    for i in [3, 8, 9, 10, 11, 20]:
        value = uc.reg_read(UC_ARM64_REG_X0 + i)
        debugPrint("; X%d: 0x%08X" % (i, value), end="")
    debugPrint("; W13=0x%X" % uc.reg_read(UC_ARM64_REG_W13), end="")
    debugPrint("; W14=0x%X" % uc.reg_read(UC_ARM64_REG_W14), end="")
    debugPrint("; W15=0x%X" % uc.reg_read(UC_ARM64_REG_W15), end="")
    debugPrint("; FP/X29=0x%X" % uc.reg_read(UC_ARM64_REG_FP), end="")
    #print("; *347c40=0x%08X" % int.from_bytes(uc.mem_read(0x347c40, 4), 'little'), end="")
    debugPrint("")

def hook_block(uc, address, size, user_data):
    vm = user_data
    assert(vm.uc == uc)

    pass #print("         >>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

def hook_stub(uc, address, size, user_data):
    vm = user_data
    assert(vm.uc == uc)

    assert(address >= importAddress)
    assert(address < importAddress + 0x01000000 * 10)

    offset = address - importAddress
    libraryIndex = offset // 0x01000000
    symbolIndex = (offset % 0x01000000) // 4
    
    #assert(libraryIndex == 0)
    library = vm.loadedLibraries[libraryIndex]

    symbolName = symbolNameByIndex(library, symbolIndex)

    lr = uc.reg_read(UC_ARM64_REG_LR)

    #print("stub", "0x%X" % lr, uc, address, size, user_data, end=" :: ")
    #print(libraryIndex, library.name, symbolIndex, symbolName)
    
    if symbolName in stubbedFunctions:
        stubbedFunctions[symbolName](vm)
        #assert(False)
    else:
        debugPrint(symbolName)
        assert(False)

    #time.sleep(0.1)
    return True


class Vm():
    def __init__(self, uc):
        self.uc = uc
        self.loadedLibraries = []
        self.tempAllocator = Allocator(0x800000000, 0x10000000)
        self.libraryAllocator = Allocator(0x00100000, 0x90000000)

#FIXME: Hide these functions or move them to a separate package; they are only used internally
def createVm():
    # Startup a unicorn-engine instance as VM backend
    if arch == "x86":
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
    elif arch == "x86_64":
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
    elif arch == "armeabi-v7a":
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    elif arch == "arm64-v8a":
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    else:
        assert(False)

    # Register a fake return address
    uc.mem_map(returnAddress, 0x1000)

    # Register some memory for malloc
    uc.mem_map(mallocAddress, mallocSize)

    # Register a fake stack
    uc.mem_map(stackAddress, stackSize)

    vm = Vm(uc)

    # Debug hooks
    uc.hook_add(UC_HOOK_BLOCK, hook_block, vm)
    #uc.hook_add(UC_HOOK_CODE, hook_code, vm)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid, vm)

    # Add a region for imports
    importCount = importSize // 4
    for i in range(10):
        libraryImportAddress = importAddress + i * 0x01000000
        uc.mem_map(libraryImportAddress, importSize)
        uc.mem_write(libraryImportAddress, b'\xc0\x03\x5f\xd6' * importCount) # RET instruction
        uc.hook_add(UC_HOOK_CODE, hook_stub, vm, libraryImportAddress, libraryImportAddress + importSize - 1)    

    
    return vm
    

class Allocator():

    def __init__(self, base, size):
        self.__base = base
        self.__size = size
        self.__offset = 0

    def alloc(self, size):
        address = self.__base + self.__offset
    
        # Align to pagesize bytes
        length = size
        length += 0xFFF
        length &= ~0xFFF

        self.__offset += length
        assert(self.__offset < self.__base + self.__size)

        return address

def roundUp(size, pageSize):
    alignedSize = size
    alignedSize += pageSize - 1
    alignedSize &= ~(pageSize - 1)
    paddingSize = alignedSize - size
    return alignedSize, paddingSize

def allocData(vm, data):
    uc = vm.uc

    length, paddingSize = roundUp(len(data), 0x1000)
    address = vm.tempAllocator.alloc(length)
    
    debugPrint("Allocating at 0x%X; bytes 0x%X/0x%X" % (address, len(data), length))
    uc.mem_map(address, length)
    uc.mem_write(address, data + b'\xCC' * paddingSize)

    return address

def allocTemporary(vm, length):
    return allocData(vm, b'\xAA' * length)

def invoke_cdecl(vm, address, args):
    uc = vm.uc
    lr = returnAddress
    for i, value in enumerate(args):
        assert(i <= 28)
        uc.reg_write(UC_ARM64_REG_X0 + i, value)
        debugPrint("X%d: 0x%08X" % (i, value))
    debugPrint("Calling 0x%X" % address)
    uc.reg_write(UC_ARM64_REG_SP, stackAddress + stackSize)
    uc.reg_write(UC_ARM64_REG_LR, lr)
    #uc.reg_write(UC_ARM64_REG_FP, stackAddress + stackSize)
    uc.emu_start(address, lr)
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    return x0



#FIXME: Move into a separate function
#FIXME: Download this file
# Development was done on https://web.archive.org/web/20231226115856/https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk
#FIXME: I attempted to do partial downloads, but unfortunately we can't download just the ZIP footer from the file.
#       While the server does range-requests, it only allows gzip encoding and then we are missing some data to decompress.
if False:
    url = "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk"
    res = requests.get(url, headers={
        "Accept-Encoding": "gzip", # "identity" here, will freeze the transfer
    #    "Cache-Control": "max-age=0", # We don't want a gzipped response
    #    "Range": "bytes=0-500",
    }, stream=True)
    data = res.raw.read()
    open("tmp.apk", "wb").write(data)
    #print(data.hex())
    #assert(False)


#arch = "armeabi-v7a"
arch = "arm64-v8a"
#arch = "x86_64"
#arch = "x86"

files = {}
libraryNames = [
    "libstoreservicescore.so",
    "libCoreADI.so",
]
with ZipFile('applemusic.apk') as apk:
    for libraryName in libraryNames:
        files[libraryName] = apk.read("lib/" + arch + "/" + libraryName)




class ClientProvisioningIntermediateMetadata():
    def __init__(self, adiInstance, cpim, session):
        self.adi = adiInstance
        self.client_provisioning_intermediate_metadata = cpim
        self.session = session

class OneTimePassword():
    def __init__(self, adiInstance, oneTimePassword, machineIdentifier):
        self.adi = adiInstance
        self.one_time_password = oneTimePassword
        self.machine_identifier = machineIdentifier

def write_u64(vm, address, value):
    return write_data(vm, address, int.to_bytes(value, 8, 'little', signed=False))
def write_u32(vm, address, value):
    return write_data(vm, address, int.to_bytes(value, 4, 'little', signed=False))
def read_u64(vm, address):
    return int.from_bytes(read_data(vm, address, 8), 'little', signed=False)
def read_u32(vm, address):
    return int.from_bytes(read_data(vm, address, 4), 'little', signed=False)



def uTo_s32(value):
    bytes = int.to_bytes(value, 4, 'little', signed=False)
    return int.from_bytes(bytes, 'little', signed=True)

def uTo_s64(value):
    bytes = int.to_bytes(value, 8, 'little', signed=False)
    return int.from_bytes(bytes, 'little', signed=True)
    
def sTo_u32(value):
    bytes = int.to_bytes(value, 4, 'little', signed=True)
    return int.from_bytes(bytes, 'little', signed=False)

def sTo_u64(value):
    bytes = int.to_bytes(value, 8, 'little', signed=True)
    return int.from_bytes(bytes, 'little', signed=False)
    



class ADI():
    def __init__(self, libraryPath):
        debugPrint("Constructing ADI for '%s'" % libraryPath)

        self.__vm = createVm()

        storeservicecoreLibrary = loadLibrary(self.__vm, "libstoreservicescore.so")

        debugPrint("Loading Android-specific symbols...")

        self.__pADILoadLibraryWithPath = resolveSymbolByName(storeservicecoreLibrary, "kq56gsgHG6")
        self.__pADISetAndroidID = resolveSymbolByName(storeservicecoreLibrary, "Sph98paBcz")
        self.__pADISetProvisioningPath = resolveSymbolByName(storeservicecoreLibrary, "nf92ngaK92")

        debugPrint("Loading ADI symbols...")

        self.__pADIProvisioningErase = resolveSymbolByName(storeservicecoreLibrary, "p435tmhbla")
        self.__pADISynchronize = resolveSymbolByName(storeservicecoreLibrary, "tn46gtiuhw")
        self.__pADIProvisioningDestroy = resolveSymbolByName(storeservicecoreLibrary, "fy34trz2st")
        self.__pADIProvisioningEnd = resolveSymbolByName(storeservicecoreLibrary, "uv5t6nhkui")
        self.__pADIProvisioningStart = resolveSymbolByName(storeservicecoreLibrary, "rsegvyrt87")
        self.__pADIGetLoginCode = resolveSymbolByName(storeservicecoreLibrary, "aslgmuibau")
        self.__pADIDispose = resolveSymbolByName(storeservicecoreLibrary, "jk24uiwqrg")
        self.__pADIOTPRequest = resolveSymbolByName(storeservicecoreLibrary, "qi864985u0")

        self.load_library(libraryPath)

    @property
    def provisioning_path(self):
        return self._provisioning_path

    @provisioning_path.setter
    def provisioning_path(self, value):
        pPath = allocData(self.__vm, value.encode('utf-8') + b'\x00')
        invoke_cdecl(self.__vm, self.__pADISetProvisioningPath, [pPath])
        self._provisioning_path = value

    @property
    def identifier(self):
        return self._identifier

    @identifier.setter
    def identifier(self, value):
        self._identifier = value
        debugPrint("Setting identifier %s" % value)
        identifier = value.encode('utf-8')
        pIdentifier = allocData(self.__vm, identifier)
        invoke_cdecl(self.__vm, self.__pADISetAndroidID, [pIdentifier, len(identifier)])

    def load_library(self, libraryPath):
        pLibraryPath  = allocData(self.__vm, libraryPath.encode('utf-8') + b'\x00')
        invoke_cdecl(self.__vm, self.__pADILoadLibraryWithPath, [pLibraryPath])
    def erase_provisioning(self):
        assert(False)
    def synchronize(self):
        assert(False)
    def destroy_provisioning(self):
        assert(False)
    def end_provisioning(self, session, persistentTokenMetadata, trustKey):

        pPersistentTokenMetadata = allocData(self.__vm, persistentTokenMetadata)
        pTrustKey = allocData(self.__vm, trustKey)


        ret = invoke_cdecl(self.__vm, self.__pADIProvisioningEnd, [
            session,
            pPersistentTokenMetadata,
            len(persistentTokenMetadata),
            pTrustKey,
            len(trustKey)
        ])

        debugPrint("0x%X" % session)
        debugPrint(persistentTokenMetadata.hex(), len(persistentTokenMetadata))
        debugPrint(trustKey.hex(), len(trustKey))

        debugPrint("%s: %X=%d" % ("pADIProvisioningEnd", ret, uTo_s32(ret)))
        assert(ret == 0)

    def start_provisioning(self, dsId, serverProvisioningIntermediateMetadata):
        debugPrint("ADI.start_provisioning")
        #FIXME: !!!

        pCpim = allocTemporary(self.__vm, 8) # ubyte*
        pCpimLength = allocTemporary(self.__vm, 4) # uint
        pSession = allocTemporary(self.__vm, 4) # uint
        pServerProvisioningIntermediateMetadata = allocData(self.__vm, serverProvisioningIntermediateMetadata)
        debugPrint("0x%X" % dsId)
        debugPrint(serverProvisioningIntermediateMetadata.hex())

        ret = invoke_cdecl(self.__vm, self.__pADIProvisioningStart, [
            dsId,
            pServerProvisioningIntermediateMetadata,
            len(serverProvisioningIntermediateMetadata),
            pCpim,
            pCpimLength,
            pSession
        ])
        debugPrint("%s: %X=%d" % ("pADIProvisioningStart", ret, uTo_s32(ret)))
        assert(ret == 0)


        # Readback output
        cpim = read_u64(self.__vm, pCpim)
        debugPrint("Wrote data to 0x%X" % cpim)
        cpimLength = read_u32(self.__vm, pCpimLength)
        cpimBytes = read_data(self.__vm, cpim, cpimLength)
        session = read_u32(self.__vm, pSession)

        debugPrint(cpimLength, cpimBytes.hex(), session)
        #assert(False)
        return ClientProvisioningIntermediateMetadata(self, cpimBytes, session)
    def is_machine_provisioned(self, dsId):
        debugPrint("ADI.is_machine_provisioned")


        errorCode = uTo_s32(invoke_cdecl(self.__vm, self.__pADIGetLoginCode, [dsId]))

        if (errorCode == 0):
            return True
        elif (errorCode == -45061):
            return False
        
        debugPrint("Unknown errorCode in is_machine_provisioned: %d=0x%X" % (errorCode, errorCode))
        assert(False)

    def dispose(self):
        assert(False)
    def request_otp(self, dsId):
        debugPrint("ADI.request_otp")
        #FIXME: !!!

        pOtp = allocTemporary(self.__vm, 8)
        pOtpLength = allocTemporary(self.__vm, 4)
        pMid = allocTemporary(self.__vm, 8)
        pMidLength = allocTemporary(self.__vm, 4)

        #ubyte* otp;
        #uint otpLength;
        #ubyte* mid;
        #uint midLength;

        ret = invoke_cdecl(self.__vm, self.__pADIOTPRequest, [
            dsId,
            pMid,
            pMidLength,
            pOtp,
            pOtpLength
        ])
        debugPrint("%s: %X=%d" % ("pADIOTPRequest", ret, uTo_s32(ret)))
        assert(ret == 0)
        
        otp = read_u64(self.__vm, pOtp)
        otpLength = read_u32(self.__vm, pOtpLength)
        otpBytes = read_data(self.__vm, otp, otpLength)

        mid = read_u64(self.__vm, pMid)
        midLength = read_u32(self.__vm, pMidLength)
        midBytes = read_data(self.__vm, mid, midLength)

        return OneTimePassword(self, otpBytes, midBytes)


class ProvisioningSession():

    def __get(self, url, extraHeaders, cacheKey=None):
        if enableCache and cacheKey != None:
            try:
                return open(cacheKey, "rb").read()
            except:
                pass
        headers = self.__headers | extraHeaders
        response = requests.get(url, headers=headers, verify=False)
        if cacheKey != None:
            open(cacheKey + "-head", "wb").write(json.dumps(headers, indent=2).encode('utf-8'))
            open(cacheKey, "wb").write(response.content)
        return response.content

    def __post(self, url, data, extraHeaders, cacheKey=None):
        if enableCache and cacheKey != None:
            try:
                return open(cacheKey, "rb").read()
            except:
                pass
        headers = self.__headers | extraHeaders
        response = requests.post(url, data=data, headers=headers, verify=False)
        if cacheKey != None:
            open(cacheKey + "-head", "wb").write(json.dumps(headers, indent=2).encode('utf-8'))
            open(cacheKey + "-req", "wb").write(data.encode('utf-8'))
            open(cacheKey, "wb").write(response.content)
        return response.content

    def __init__(self, adi, device):

        self.adi = adi
        self.device = device

        self.__urlBag = {}

        self.__headers = {
            "User-Agent": "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0",

            # they are somehow not using the plist content-type in AuthKit
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "keep-alive",

            "X-Mme-Device-Id": device.unique_device_identifier,
            # on macOS, MMe for the Client-Info header is written with 2 caps, while on Windows it is Mme...
            # and HTTP headers are supposed to be case-insensitive in the HTTP spec...
            "X-MMe-Client-Info": device.server_friendly_description,
            "X-Apple-I-MD-LU": device.local_user_uuid,

            # "X-Apple-I-MLB": device.logicBoardSerialNumber, // 17 letters, uppercase in Apple's base 34
            # "X-Apple-I-ROM": device.romAddress, // 6 bytes, lowercase hexadecimal
            # "X-Apple-I-SRL-NO": device.machineSerialNumber, // 12 letters, uppercase

            # different apps can be used, I already saw fmfd and Setup here
            # and Reprovision uses Xcode in some requests, so maybe it is possible here too.
            "X-Apple-Client-App-Name": "Setup",
        }

        return
    def load_url_bag(self):
        content = self.__get("https://gsa.apple.com/grandslam/GsService2/lookup", {}, "cache/lookup.xml")
        plist = plistlib.loads(content)
        urls =  plist['urls']
        for urlName, url in urls.items():
            self.__urlBag[urlName] = url

    def __time(self):
        # Replaces Clock.currTime().stripMilliseconds().toISOExtString()
        return datetime.datetime.now().replace(microsecond=0).isoformat()

    def provision(self, dsId):
        debugPrint("ProvisioningSession.provision")
        #FIXME: !!!


        if (len(self.__urlBag) == 0):
            self.load_url_bag()

        extraHeaders = {
            "X-Apple-I-Client-Time": self.__time()
        }
        startProvisioningPlist = self.__post(self.__urlBag["midStartProvisioning"],
        """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Header</key>
\t<dict/>
\t<key>Request</key>
\t<dict/>
</dict>
</plist>""", extraHeaders, "cache/midStartProvisioning.xml")

        spimPlist = plistlib.loads(startProvisioningPlist)
        spimResponse = spimPlist['Response']
        spimStr = spimResponse["spim"]
        debugPrint(spimStr)

        spim = base64.b64decode(spimStr)

        cpim = self.adi.start_provisioning(dsId, spim)
        #FIXME: scope (failure) try { adi.destroyProvisioning(cpim.session); } catch(Throwable) {}

        debugPrint(cpim.client_provisioning_intermediate_metadata.hex())

        extraHeaders = {
            "X-Apple-I-Client-Time": self.__time()
        }
        endProvisioningPlist = self.__post(self.__urlBag["midFinishProvisioning"], """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Header</key>
\t<dict/>
\t<key>Request</key>
\t<dict>
\t\t<key>cpim</key>
\t\t<string>%s</string>
\t</dict>
</dict>
</plist>""" % (base64.b64encode(cpim.client_provisioning_intermediate_metadata).decode('utf-8')), extraHeaders, "cache/midFinishProvisioning.xml")



        plist = plistlib.loads(endProvisioningPlist)
        spimResponse = plist["Response"]

        #scope ulong routingInformation;
        #routingInformation = to!ulong(spimResponse["X-Apple-I-MD-RINFO"])
        persistentTokenMetadata = base64.b64decode(spimResponse["ptm"])
        trustKey = base64.b64decode(spimResponse["tk"])

        self.adi.end_provisioning(cpim.session, persistentTokenMetadata, trustKey)

        return
    
uniqueDeviceIdentifierJson = "UUID"
serverFriendlyDescriptionJson = "clientInfo"
adiIdentifierJson = "identifier"
localUserUUIDJson = "localUUID"

class Device():
    def __init__(self, path):
    
        debugPrint("Constructing Device for '%s'" % path)

        self.__path = path

        # Attempt to load the JSON
        try:
            dataBytes = open(self.__path, "rb").read()
            data = json.loads(dataBytes.decode('utf-8'))
            self._unique_device_identifier = data[uniqueDeviceIdentifierJson]
            self._server_friendly_description = data[serverFriendlyDescriptionJson]
            self._adi_identifier = data[adiIdentifierJson] 
            self._local_user_uuid = data[localUserUUIDJson]
            self._initialized = True
            return
        except FileNotFoundError:
            pass

        self._unique_device_identifier = None
        self._server_friendly_description = None
        self._adi_identifier = None
        self._local_user_uuid = None

        # This means we have not loaded data from `path`
        self._initialized = False

    def write(self, path = None):
        if path != None:
            self.__path = path

        # Save to JSON
        data = {}
        data[uniqueDeviceIdentifierJson] = self._unique_device_identifier
        data[serverFriendlyDescriptionJson] = self._server_friendly_description
        data[adiIdentifierJson] = self._adi_identifier
        data[localUserUUIDJson] = self._local_user_uuid
        dataBytes = json.dumps(data, indent=2).encode('utf-8')
        open(self.__path, "wb").write(dataBytes)

    #FIXME: setters for all properties and they auto-write in the original implementation

    @property
    def initialized(self):
        return self._initialized

    @property
    def unique_device_identifier(self):
        return self._unique_device_identifier
    
    @unique_device_identifier.setter
    def unique_device_identifier(self, value):
        self._unique_device_identifier = value
        self.write()

    @property
    def server_friendly_description(self):
        return self._server_friendly_description

    @server_friendly_description.setter
    def server_friendly_description(self, value):
        self._server_friendly_description = value
        self.write()

    @property
    def adi_identifier(self):
        return self._adi_identifier

    @adi_identifier.setter
    def adi_identifier(self, value):
        self._adi_identifier = value
        self.write()

    @property
    def local_user_uuid(self):
        return self._local_user_uuid
    
    @local_user_uuid.setter
    def local_user_uuid(self, value):
        self._local_user_uuid = value
        self.write()

    

R_AARCH64_ABS64 =          257
R_AARCH64_GLOB_DAT =      1025
R_AARCH64_JUMP_SLOT =     1026
R_AARCH64_RELATIVE =      1027


def parseElf(data):
    dataIO = BytesIO(data)
    elffile = ELFFile(dataIO)   
    return elffile

def resolveSymbolByName(library, symbolName):
    section = library.elf.get_section_by_name('.dynsym')
    assert(isinstance(section, SymbolTableSection))

    num_symbols = section.num_symbols()
    for i in range(num_symbols):
        sym = section.get_symbol(i)
        if sym.name == symbolName:
            #print(sym.__dict__)
            return resolveSymbolByIndex(library, i)
           
    assert(False)



def write_data(vm, address, data):
    vm.uc.mem_write(address, data)

def read_data(vm, address, length):
    data = vm.uc.mem_read(address, length)
    return bytes(data)

def read_cstr(vm, address):
    maxLength = 0x1000
    s = read_data(vm, address, maxLength)
    s, terminator, _ = s.partition(b'\x00')
    assert(terminator == b'\x00')
    return s


def hook_emptyStub(vm):
    vm.uc.reg_write(UC_ARM64_REG_X0, 0)

mallocAllocator = Allocator(mallocAddress, mallocSize)
def hook_malloc(vm):
    uc = vm.uc
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    debugTrace("malloc(0x%X)" % x0)
    x0 = mallocAllocator.alloc(x0)
    uc.reg_write(UC_ARM64_REG_X0, x0)

hook_free = hook_emptyStub

def hook_strncpy(vm):
    uc = vm.uc

    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)

    pDst = x0
    pSrc = x1
    _len = x2

    src = read_cstr(vm, pSrc)
    if len(src) > _len:
        data = src[0:_len]
        assert(False)
    else:
        paddingSize = _len - len(src)
        data = src + b'\x00' * paddingSize

    write_data(vm, pDst, data)

    uc.reg_write(UC_ARM64_REG_X0, pDst)


def hook_mkdir(vm):
    uc = vm.uc

    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)

    path = read_cstr(vm, x0).decode('utf-8')
    mode = x1

    debugTrace("mkdir('%s', %s)" % (path, oct(mode)))

    assert(path in [
        "./anisette"
    ])
    assert(mode == 0o777)
    os.mkdir(path) # FIXME: mode?

    uc.reg_write(UC_ARM64_REG_X0, 0)

def hook_umask(vm):
    uc = vm.uc

    x0 = uc.reg_read(UC_ARM64_REG_X0)

    cmask = x0

    cmask = 0o777

    uc.reg_write(UC_ARM64_REG_X0, cmask)

def hook_chmod(vm):
    uc = vm.uc

    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)

    path = read_cstr(vm, x0).decode('utf-8')
    mode = x1

    debugTrace("chmod('%s', %s)" % (path, oct(mode)))

    uc.reg_write(UC_ARM64_REG_X0, 0)



# Based on https://github.com/Dadoum/Provision/blob/main/lib/std_edit/linux_stat.d (aarch64)
#FIXME: These must be changed to fixed size types
c_dev_t = c_uint32
c_off_t = c_size_t
c_ino_t = c_uint64
c_mode_t = c_uint32 #c_ushort
c_nlink_t = c_uint32
c_uid_t = c_uint32
c_gid_t = c_uint32
c_blksize_t = c_ulong
c_blkcnt_t = c_uint64
c_time_t = c_uint64
c_suseconds_t = c_long

class c_timeval(Structure):
    _fields_ = [
        ("tv_sec", c_time_t),        # /* seconds since Jan. 1, 1970 */
        ("tv_usec", c_suseconds_t)   # /* and microseconds */
    ]

class c_stat(Structure):
    _fields_ = [        
        ("st_dev", c_dev_t),         # /* ID of device containing file */
        ("st_ino", c_ino_t),         # /* inode number */
        ("st_mode", c_mode_t),       # /* protection */
        ("st_nlink", c_nlink_t),     # /* number of hard links */
        ("st_uid", c_uid_t),         # /* user ID of owner */
        ("st_gid", c_gid_t),         # /* group ID of owner */
        ("st_rdev", c_dev_t),        # /* device ID (if special file) */
        ("__pad1", c_dev_t),         # ???
        ("st_size", c_off_t),        # /* total size, in bytes */
        ("st_blksize", c_blksize_t), # /* blocksize for file system I/O */
        ("__pad2", c_int),           # ???
        ("st_blocks", c_blkcnt_t),   # /* number of 512B blocks allocated */
        ("st_atime", c_time_t),      # /* time of last access */
        ("st_atimensec", c_ulong),   # ?!?!
        ("st_mtime", c_time_t),      # /* time of last modification */
        ("st_mtimensec", c_ulong),   # ?!?!
        ("st_ctime", c_time_t),      # /* time of last status change */
        ("st_ctimensec", c_ulong),   # ?!?!
        ("__unused_0", c_int),       # ???
        ("__unused_1", c_int)        # ???
    ]

# From https://chromium.googlesource.com/android_tools/+/20ee6d20/ndk/platforms/android-21/arch-arm64/usr/include/sys/stat.h
comment = """
  unsigned long st_dev; \
  unsigned long st_ino; \
  unsigned int st_mode; \
  unsigned int st_nlink; \
  uid_t st_uid; \
  gid_t st_gid; \
  unsigned long st_rdev; \
  unsigned long __pad1; \
  long st_size; \
  int st_blksize; \
  int __pad2; \
  long st_blocks; \
  long st_atime; \
  unsigned long st_atime_nsec; \
  long st_mtime; \
  unsigned long st_mtime_nsec; \
  long st_ctime; \
  unsigned long st_ctime_nsec; \
  unsigned int __unused4; \
  unsigned int __unused5; \
"""

tmp = c_stat()
tmpLen = len(bytes(tmp))
#print(tmpLen)
assert(tmpLen == 128)

errnoAddress = None

ENOENT = 2

def handle_stat(vm, path, buf):

    try:
        statResult = os.stat(path)
        #print(statResult)
    except FileNotFoundError:
        print("Unable to stat '%s'" % path)
        vm.uc.reg_write(UC_ARM64_REG_X0, sTo_u64(-1))
        setErrno(vm, ENOENT)
        return

    stat = c_stat(
        st_dev=0,
        st_ino=0,
        st_mode=statResult.st_mode,
        # ...
        st_size=statResult.st_size,
        st_blksize=512,
        st_blocks=(statResult.st_size + 511) // 512,
        # ...s
    )
    stat.__byte = statResult.st_size
    statBytes = bytes(stat)
    #print(statBytes.hex(), len(statBytes))

    debugPrint("%s %s %s" % (statResult.st_size, statResult.st_blksize, statResult.st_blocks))
    debugPrint("%s %s %s" % (stat.st_size, stat.st_blksize, stat.st_blocks))

    debugPrint("0x%X = %d" % (statResult.st_mode, statResult.st_mode))
    statBytes = b"".join([
        bytes.fromhex("00000000" + "00000000" + # st_dev
                      "00000000" + "00000000") + # st_ino
        int.to_bytes(statResult.st_mode, 4, 'little') + # st_mode
        bytes.fromhex("00000000" + # st_nlink
                      "a4810000" + # st_uid
                      "00000000" + # st_gid
                      "00000000" + "00000000" + # st_rdev
                      "00000000" + "00000000"), # __pad1
        int.to_bytes(statResult.st_size, 8, 'little'),  # st_size
        bytes.fromhex("00000000" + # st_blksize
                      "00000000" + # __pad2
                      "00000000" + "00000000" + # st_blocks
                      "00000000" + "00000000" + # st_atime
                      "00000000" + "00000000" + # st_atime_nsec
                      #"00" * 4 +
                      "00" * 2 + "01" * 2 + "00000000" # st_mtime [This must have a valid value]
                       
                      "00000000" + "00000000" +  # st_mtime_nsec
                      "00000000" + "00000000" + # st_ctime
                      "00000000" + "00000000" + # st_ctime_nsec
                      "00000000" + # __unused4
                      "00000000" # __unused5
                    )
    ])
    #00000000000000000002000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    debugPrint(len(statBytes))
    assert(len(statBytes) in [104, 128])


    write_data(vm, buf, statBytes)

    # Return success
    vm.uc.reg_write(UC_ARM64_REG_X0, 0)

def hook_lstat(vm):

    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)

    pPath = x0
    path = read_cstr(vm, pPath).decode('utf-8')
    buf = x1

    debugTrace("lstat(0x%X:'%s', [...])" % (pPath, path))

    return handle_stat(vm, path, buf)


    

def hook_fstat(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)

    fildes = x0
    buf = x1

    fileIndex = fildes
    fileHandle = fileHandles[fileIndex]

    return handle_stat(vm, fileHandle.fileno(), buf)


fileHandles = []
    
O_RDONLY = 0o0
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100	
O_NOFOLLOW = 0o100000	

def hook_open(vm):
    global fileHandles
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)
    x2 = vm.uc.reg_read(UC_ARM64_REG_X2)

    path = read_cstr(vm, x0).decode('utf-8')
    oflag = x1
    mode = x2

    debugTrace("open('%s', %s, %s)" % (path, oct(oflag), oct(mode)))
    #time.sleep(2.0)
    #assert(False)

    assert(path in [
        './anisette/adi.pb'
    ])

    assert(oflag in [0o100000, 0o100101])

    if oflag & O_WRONLY:
        mode = "wb"
    else:
        mode = "rb"
    
    if oflag & O_CREAT:
        mode += "+"

    fileIndex = len(fileHandles)
    fileHandle = open(path, mode)
    fileHandles += [fileHandle]

    # Return fildes
    fildes = fileIndex
    vm.uc.reg_write(UC_ARM64_REG_X0, fildes)


def hook_ftruncate(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)

    fildes = x0
    length = x1

    debugTrace("ftruncate(%d, %d)" % (fildes, length))

    fileIndex = fildes
    fileHandle = fileHandles[fileIndex]

    fileHandle.truncate(length)

    vm.uc.reg_write(UC_ARM64_REG_X0, 0)


def hook_read(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)
    x2 = vm.uc.reg_read(UC_ARM64_REG_X2)

    fildes = x0
    buf = x1
    nbyte = x2
    
    debugTrace("read(%d, 0x%X, %d)" % (fildes, buf, nbyte))
    #assert(False)

    fileIndex = fildes
    fileHandle = fileHandles[fileIndex]

    bufBytes = fileHandle.read(nbyte)
    write_data(vm, buf, bufBytes)

    vm.uc.reg_write(UC_ARM64_REG_X0, nbyte)



def hook_write(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)
    x2 = vm.uc.reg_read(UC_ARM64_REG_X2)

    fildes = x0
    buf = x1
    nbyte = x2
    
    debugTrace("write(%d, 0x%X, %d)" % (fildes, buf, nbyte))

    fileIndex = fildes
    fileHandle = fileHandles[fileIndex]

    bufBytes = read_data(vm, buf, nbyte)
    fileHandle.write(bufBytes)

    vm.uc.reg_write(UC_ARM64_REG_X0, nbyte)


def hook_close(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)

    fildes = x0

    fileIndex = fildes
    fileHandle = fileHandles[fileIndex]

    fileHandle.close()

    vm.uc.reg_write(UC_ARM64_REG_X0, 0)

def hook_dlopenWrapper(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    path = read_cstr(vm, x0).decode('utf-8')
    libraryName = path.rpartition('/')[2]

    debugTrace("dlopen('%s' (%s))" % (path, libraryName))

    assert(libraryName in [
        "libCoreADI.so"
    ])

    library = loadLibrary(vm, libraryName)
    x0 = library.index
    vm.uc.reg_write(UC_ARM64_REG_X0, 1 + x0)

    #assert(False)

def hook_dlsymWrapper(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)
    handle = x0
    symbol = read_cstr(vm, x1).decode('utf-8')

    libraryIndex = handle - 1
    library = vm.loadedLibraries[libraryIndex]

    debugTrace("dlsym(%X (%s), '%s')" % (handle, library.name, symbol))

    symbolAddress = resolveSymbolByName(library, symbol)
    debugPrint("Found at 0x%X" % symbolAddress)

    vm.uc.reg_write(UC_ARM64_REG_X0, symbolAddress)

hook_dlcloseWrapper = hook_emptyStub

def hook_gettimeofday(vm):
    timestamp = time.time()

    cacheTime = False
    cachePath = "cache/time.bin"

    if cacheTime:
        tBytes = open(cachePath, "rb").read()
        print("Loaded time from cache!")
        t = c_timeval.from_buffer_copy(tBytes)
        print("ok", t)

    t = c_timeval(
        tv_sec = math.floor(timestamp // 1),
        tv_usec = math.floor((timestamp % 1.0) * 1000 * 1000)
    )
    tBytes = bytes(t)

    if cacheTime:
        open(cachePath, "wb").write(tBytes)

    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)

    tp = x0
    tzp = x1

    debugTrace("gettimeofday(0x%X, 0x%X)" % (tp, tzp))

    # We don't need timezone support
    assert(tzp == 0)
    comment = """
    struct timezone {
             int     tz_minuteswest; /* of Greenwich */
             int     tz_dsttime;     /* type of dst correction to apply */
    };
    """

    # Write the time
    debugPrint("%s %s %s" % (t.__dict__, tBytes.hex(), len(tBytes)))
    write_data(vm, tp, tBytes)
    
    # Return success
    vm.uc.reg_write(UC_ARM64_REG_X0, 0)

def setErrno(vm, value):
    global errnoAddress
    if errnoAddress == None:
        errnoAddress = allocTemporary(vm, 4)
    write_u32(vm, errnoAddress, value)
            
def hook___errno_location(vm):
    global errnoAddress
    if errnoAddress == None:
        debugPrint("Checking errno before first error (!)")
        setErrno(vm, 0)
    vm.uc.reg_write(UC_ARM64_REG_X0, errnoAddress)

def hook___system_property_get_impl(vm):
    x0 = vm.uc.reg_read(UC_ARM64_REG_X0)
    x1 = vm.uc.reg_read(UC_ARM64_REG_X1)
    name = read_cstr(vm, x0).decode('utf-8')
    debugTrace("__system_property_get(%s, [...])" % name)
    value = b"no s/n number"
    write_data(vm, x1, value)
    vm.uc.reg_write(UC_ARM64_REG_X0, len(value))


def hook_arc4random_impl(vm):
    value = 0xDEADBEEF # "Random number, chosen by fair dice roll"
    vm.uc.reg_write(UC_ARM64_REG_X0, value)
    
stubbedFunctions = {

    # memory management
    "malloc": hook_malloc,
    "free": hook_free,

    # string
    "strncpy": hook_strncpy,
    
    # fs
    "mkdir": hook_mkdir,
    "umask": hook_umask,
    "chmod": hook_chmod,
    "lstat": hook_lstat,
    "fstat": hook_fstat,

    # io
    "open": hook_open,
    "ftruncate": hook_ftruncate,
    "read": hook_read,
    "write": hook_write,
    "close": hook_close, 

    # dynamic symbol stuff
    "dlsym": hook_dlsymWrapper,
    "dlopen": hook_dlopenWrapper,
    "dlclose": hook_dlcloseWrapper,

    # pthreads
    "pthread_once": hook_emptyStub,
    "pthread_create": hook_emptyStub,
    "pthread_mutex_lock": hook_emptyStub,
    "pthread_rwlock_unlock": hook_emptyStub,
    "pthread_rwlock_destroy": hook_emptyStub,    
    "pthread_rwlock_wrlock": hook_emptyStub,
    "pthread_rwlock_init": hook_emptyStub,
    "pthread_mutex_unlock": hook_emptyStub,
    "pthread_rwlock_rdlock": hook_emptyStub,

    # date and time
    "gettimeofday": hook_gettimeofday,
    
    # misc
    "__errno": hook___errno_location,
    "__system_property_get": hook___system_property_get_impl,
    "arc4random": hook_arc4random_impl,
}

class Library():
    def __init__(self, name, elf, base, index):
        self.name = name
        self.elf = elf
        self.base = base
        self.symbols = {}
        self.index = index

def resolveSymbolByIndex(library, symbolIndex):
    #for section in elf.iter_sections():
    #   print(section)
    if symbolIndex in library.symbols:
        #print("Resolving symbol 0x%X from symbols dict" % symbolIndex)
        return library.symbols[symbolIndex]

    section = library.elf.get_section_by_name('.dynsym')
    assert(isinstance(section, SymbolTableSection))
        
    sym = section.get_symbol(symbolIndex)
    #print("Resolving symbol 0x%X relative to base" % symbolIndex, sym.__dict__)

    #if sym['st_shndx'] == 11:
    #    section = library.elf.get_section(sym['st_shndx'])
    #    print("Fixing section", section.__dict__)
    #    print("0x%X" % (section['sh_addr'] + sym['st_value']))
    #    assert(False)

    return library.base + sym['st_value']
            
    assert(False)

def symbolNameByIndex(library, symbolIndex):
    section = library.elf.get_section_by_name('.dynsym')
    assert(isinstance(section, SymbolTableSection))
        
    sym = section.get_symbol(symbolIndex)
    return sym.name



def loadLibrary(vm, libraryName):

    # Do not load the same library multiple times
    for library in vm.loadedLibraries:
        debugPrint("Comparing '%s' to loaded library '%s'" % (libraryName, library.name))
        if library.name == libraryName:
            debugPrint("Library already loaded")
            return library

    uc = vm.uc

    libraryIndex = len(vm.loadedLibraries)
    elfData = files[libraryName]

    elf = parseElf(elfData)

    chosenBase = vm.libraryAllocator.alloc(0x10000000)

    library = Library(libraryName, elf, chosenBase, libraryIndex)

    # Stub all imports
    section = library.elf.get_section_by_name('.dynsym')
    num_symbols = section.num_symbols()
    for i in range(num_symbols):
        sym = section.get_symbol(i)
        #print(sym.name)

        #print(sym.__dict__)
        #print(sym['st_shndx'])
        if sym['st_shndx'] == 'SHN_UNDEF':
            library.symbols[i] = importAddress + libraryIndex * 0x01000000 + i * 4
            #print("Registering 0x%X: %s" % (library.symbols[i], sym.name))

            #print("%s: 0x%X" % (sym.name, resolveSymbolByIndex(library, i)))


    for segment in elf.iter_segments():
        address = chosenBase + segment['p_vaddr']
        size = segment['p_memsz']

        addressStart = address
        addressEnd = address + size

        alignment = segment['p_align']

        # Align the start
        addressStart &= ~(alignment - 1)

        # Align the end
        addressEnd += alignment - 1
        addressEnd &= ~(alignment - 1)

        # Fix size for new alignment
        size = addressEnd - address

        dataOffset = segment['p_offset']
        dataSize = segment['p_filesz']
        paddingBeforeSize = address - addressStart
        paddingAfterSize = size - dataSize

        debugPrint("Mapping at 0x%X-0x%X (0x%X-0x%X); bytes 0x%X" % (addressStart, addressEnd, address, address + size - 1, size))

        if segment['p_type'] == 'PT_LOAD':
            data = b'\x00' * paddingBeforeSize + elfData[dataOffset:dataOffset+dataSize] + b'\x00' * paddingAfterSize
            uc.mem_map(addressStart, len(data))
            uc.mem_write(addressStart, data)
        else:
            debugPrint("- Skipping %s" % (segment.__dict__))

    def relocateSection(sectionName):
            
        reladyn = elf.get_section_by_name(sectionName)
        assert(isinstance(reladyn, RelocationSection))

        for reloc in reladyn.iter_relocations():

            #print('    Relocation (%s)' % 'RELA' if reloc.is_RELA() else 'REL', end="")
            # Relocation entry attributes are available through item lookup
            #print('      offset = 0x%X' % reloc['r_offset'])
            #print("%s" % reloc.__dict__, end="")
            #print("")

            type = reloc['r_info_type']
            address = chosenBase + reloc['r_offset']

            if type == R_AARCH64_ABS64:
                symbolIndex = reloc['r_info_sym']
                symbolAddress = resolveSymbolByIndex(library, symbolIndex)
                uc.mem_write(address, int.to_bytes(symbolAddress + reloc['r_addend'], 8, 'little')) #b'\x12\x34\x22\x78\xAB\xCD\xEF\xFF')
            elif type == R_AARCH64_GLOB_DAT:
                symbolIndex = reloc['r_info_sym']
                symbolAddress = resolveSymbolByIndex(library, symbolIndex)
                uc.mem_write(address, int.to_bytes(symbolAddress + reloc['r_addend'], 8, 'little')) #b'\x12\x34\x22\x78\xAB\xCD\xEF\xFF')
            elif type == R_AARCH64_JUMP_SLOT:
                symbolIndex = reloc['r_info_sym']
                symbolAddress = resolveSymbolByIndex(library, symbolIndex)
                uc.mem_write(address, int.to_bytes(symbolAddress, 8, 'little')) #b'\x12\x34\x11\x78\xAB\xCD\xEF\xFF')
            elif type == R_AARCH64_RELATIVE:
                uc.mem_write(address, int.to_bytes(chosenBase + reloc['r_addend'], 8, 'little')) #b'\x12\x34\x22\x78\xAB\xCD\xEF\xFF')
            else:
                assert(False)
    relocateSection('.rela.dyn')
    relocateSection('.rela.plt')

    # Loop over each initializer?!

    vm.loadedLibraries += [library]
    return library




# Quick tool to test some functionality
def main():
    import uuid

    #import pyprovision
    pyprovision = sys.modules[__name__]

    from ctypes import c_ulonglong
    import secrets
    adi = pyprovision.ADI("./anisette/")
    adi.provisioning_path = "./anisette/"
    device = pyprovision.Device("./anisette/device.json")
    if not device.initialized:
        print("Initializing device")
        # Pretend to be a MacBook Pro
        device.server_friendly_description = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
        device.unique_device_identifier = str(uuid.uuid4()).upper()
        device.adi_identifier = secrets.token_hex(8).lower()
        device.local_user_uuid = secrets.token_hex(32).upper()
    else:
        print("(Device initialized: server-description='%s' device-uid='%s' adi='%s' user-uid='%s'" % (device.server_friendly_description, device.unique_device_identifier, device.adi_identifier, device.local_user_uuid))
    adi.identifier = device.adi_identifier
    dsid = c_ulonglong(-2).value
    is_prov = adi.is_machine_provisioned(dsid)
    if not is_prov:
        print("Provisioning...")
        provisioning_session = pyprovision.ProvisioningSession(adi, device)
        provisioning_session.provision(dsid)
    else:
        print("(Already provisioned)")
    otp = adi.request_otp(dsid)
    a = {"X-Apple-I-MD": base64.b64encode(bytes(otp.one_time_password)).decode(), "X-Apple-I-MD-M": base64.b64encode(bytes(otp.machine_identifier)).decode()}
    #a.update(generate_meta_headers(user_id=USER_ID, device_id=DEVICE_ID))
    
    print(a)

if __name__ == "__main__":
    main()