package PigasusTypes;

import Vector::*;

// Packet Data : 520 bits
typedef struct {
    Bit#(512)   data;   // payload
    Bit#(6)     empty;  // inform the len of empty payload
    Bit#(1)     sop;    // start of pkt
    Bit#(1)     eop;    // end of pkt
} PktT deriving(Bits, Eq);

// Metadata : 252 bits
typedef struct {
    Bit#(8)   prot;           // 8  : Protocol (TCP/UDP 등)
    Bit#(96)  tuple;          // 96 : 5-Tuple (Src/Dst IP, Src/Dst Port)
    Bit#(32)  seq;            // 32 : TCP Sequence Number (Reassembler 용도)
    Bit#(16)  len;            // 16 : Payload Length
    Bit#(10)  pktID;          // 10 : Packet Buffer의 저장 위치 (Free-list에서 받아옴)
    Bit#(6)   empty;          // 6  : (패킷 정렬/길이 관련 추가 정보)
    Bit#(5)   flits;          // 5  : 이 패킷이 총 몇 개의 플릿(512b)으로 이루어졌는지
    Bit#(9)   hdr_len;        // 9  : 헤더의 총 길이
    Bit#(9)   tcp_flags;      // 9  : TCP Control Flags (SYN, ACK 등)
    Bit#(3)   pkt_flags;      // 3  : 패킷 상태 플래그
    Bit#(2)   pdu_flag;       // 2  : PDU 생성 관련 플래그
    Bit#(56)  last_7_bytes;   // 56 : Shift-OR 필터링 최적화를 위한 마지막 바이트 조각
} MetadataT deriving(Bits, Eq, FShow);


// FPSM
typedef Bit#(256) MatchVec;

endpackage
