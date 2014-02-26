from os.path import exists, expanduser, split
from os import makedirs

doc = Document.getCurrentDocument()

# disasm doc
seg = doc.getCurrentSegment()
seg.disassembleWholeSegment()

# iterate through segments, mark all procs
addr = seg.getStartingAddress()
last = addr + seg.getLength()
while addr < last:
    addr=seg.getNextAddressWithType(addr,Segment.TYPE_CODE)
    if addr == Segment.BAD_ADDRESS:
        break

    # Look for the "push ebp / mov ebp, esp" pattern
    if doc.is64Bits() and seg.readByte(addr) == 0x55 and seg.readByte(addr + 1) == 0x48 and seg.readByte(addr + 2) == 0x89 and seg.readByte(addr + 3) == 0xE5:
        seg.markAsProcedure(addr)
    if not doc.is64Bits() and seg.readByte(addr) == 0x55 and seg.readByte(addr + 1) == 0x89 and seg.readByte(addr + 2) == 0xE5:
        seg.markAsProcedure(addr)

    addr = addr + 1

# get proc count
procCount = seg.getProcedureCount()
i = 0
homeDir = expanduser("~")
head, appName = split(doc.getExecutableFilePath())
path = homeDir + '/hopperDumps/' + appName + '/'
if not exists(path):
    makedirs(path)

# iterate through procs
while i < procCount:
    # get proc
    proc = seg.getProcedureAtIndex(i)
    # get proc's name
    name = seg.getNameAtAddress(proc.getEntryPoint())

    # clean the name of any unsavoury chars
    items = ["[", "]", ":"]
    for item in items:
        name = name.replace(item, "")
    name = name.replace(" ", "___")
    name = name.replace("+", "_classMessage_")
    name = name.replace("-", "_instanceMessage_")
    
    # grab the decompilation
    output = proc.decompile()

    # open up a file handler for the name
    with open(path + name +'.pseu', 'w') as outFile:
        # write the decompilation to disk
        outFile.write(output + '\n')
    # inc counter
    i = i + 1

# inform user of successful export
print "[*] Pseudo code export complete. Export located at: %s" % (path)

