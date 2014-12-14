def svcCall(seg, adr):
    #(0x80 == 128) (0xDF == 223)    
    if seg.readByte(adr) == 128 and seg.readByte(adr + 1) == 223:
        return True
    return False

doc = Document.getCurrentDocument()

for seg_id in range(0, doc.getSegmentCount()):
    seg = doc.getSegment(seg_id)

    seg_start = seg.getStartingAddress()
    seg_stop = seg_start + seg.getLength()

    adr = seg_start
    while adr + 1 <= seg_stop:
        if svcCall(seg, adr):
            print("[+] SVC found at: %s", hex(adr))
        adr += 1

