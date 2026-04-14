package KernelTypes;

import Vector::*;

// Memory port definitions (bluevitis KernelMain convention)
typedef 2 MemPortCnt;
typedef struct {
    Bit#(64) addr;
    Bit#(32) bytes;
} MemPortReq deriving (Eq, Bits);

interface MemPortIfc;
    method ActionValue#(MemPortReq) readReq;
    method ActionValue#(MemPortReq) writeReq;
    method ActionValue#(Bit#(512)) writeWord;
    method Action readWord(Bit#(512) word);
endinterface

endpackage
