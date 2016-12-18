import struct
import sys
sys.path.insert(0,"./Virtual-Address-Space-Research")
import VirtualAddressSpaceExplorer as vas

moduleNameToAttributes = {"vmxnet3":{"main":[0xffffffffa0000000L,50657], "text": [0xffffffffa0000000, 0x7808], "text.unlikely":[0xffffffffa0007808,0x32], "init.text":[0xffffffffa000e000,0x3c]}}

def packedStringAt(address, size):
    return vas.addressSpace.zread(address, size + 1)

def byteListAt(address,size):
    packedStr = packedStringAt(address, size)
    
    if packedStr is None:
        return
    
    return list(struct.unpack('<'+str(size)+'B', packedStr))

def getModuleAddress(name, section):
    return moduleNameToAttributes[name][section][0]

def getModuleSize(name, section):
    return moduleNameToAttributes[name][section][1]

#note: this doesn't find multiple appearances in same page..
def searchAddressSpaceForPackedStr(packedStr):
    for page,size in vas.addressSpace.get_available_pages():
        if vas.isKernelSpaceAddress(page):
            packedPage = packedStringAt(page, size)
            if packedStr in packedPage:
                yield page + packedPage.index(packedStr)

def searchAddressSpaceForBytes(bs):
    return searchAddressSpaceForPackedStr(struct.pack('<'+str(len(bs))+'B', *bs))

elf_magic = [0x7F, 0x45, 0x4C, 0x46, 0x02,0x01, 1, 0,0, 0,0, 0,0, 0,0]

for module in moduleNameToAttributes.keys():
    for section in moduleNameToAttributes[module].keys():
        with file("Resources/"+module+'_'+section+'.elf','wb') as f:
            packedStr = packedStringAt(getModuleAddress(module,section),getModuleSize(module, section))
            
            if not packedStr is None:
                f.write(packedStr)
            else:
                print "returned none from read"

vas.printKernelExecutableRanges()
                
i = 0
for (startAddress,endAddress) in vas.locateKernelExecutableRanges():
    with file("Resources\\Executable Ranges\\"+str(i)+".bin",'wb') as f:
        packedStr = packedStringAt(startAddress, endAddress - startAddress - 1)             
        if not packedStr is None:
            f.write(packedStr)
        i+=1