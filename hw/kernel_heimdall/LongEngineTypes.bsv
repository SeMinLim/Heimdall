package LongEngineTypes;

import Vector::*;

// Packet geometry
typedef 64  NumPayloadBytes;
typedef 57  NumLanes;         // = 64 - 8 + 1

typedef Bit#(512)  Payload;       // 64 bytes = 512 bits
typedef Bit#(16)   PayloadLen;    // from i_rx_info[15:0], max 64
typedef Bit#(64)   LaneData;      // each lane: 8 bytes

typedef Bit#(57)   ValidMaskBits; // one bit per lane

typedef 19 PreFilterAddrBits;
typedef TExp#(PreFilterAddrBits) PreFilterNumEntries;
typedef Bit#(PreFilterAddrBits) PreFilterAddr;
typedef Bit#(1) PreFilterBit;

function PreFilterAddr reduceCrc32ToPreFilterAddr(Bit#(32) hash);
	PreFilterAddr lower = hash[18:0];
	PreFilterAddr upper = hash[31:13];
	return lower ^ upper;
endfunction

endpackage
