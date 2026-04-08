package LongEngineTypes;

import Vector::*;

// Packet geometry
typedef 64  NumPayloadBytes;
typedef 57  NumLanes;         // = 64 - 8 + 1

typedef Bit#(512)  Payload;       // 64 bytes = 512 bits
typedef Bit#(16)   PayloadLen;    // from i_rx_info[15:0], max 64
typedef Bit#(64)   LaneData;      // each lane: 8 bytes

typedef Bit#(57)   ValidMaskBits; // one bit per lane

endpackage
