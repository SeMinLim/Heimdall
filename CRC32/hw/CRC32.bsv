package CRC32;


// CRC32 (IEEE 802.3) and CRC32C (Castagnoli)
// Reflected algorithm — processes LSB first.
//   CRC32  poly: 0xEDB88320
//   CRC32C poly: 0x82F63B78

// One-bit CRC step: shift right, conditionally XOR polynomial
function Bit#(32) crcBit(Bit#(32) crc, Bit#(32) poly);
    return (crc[0] == 1) ? ((crc >> 1) ^ poly) : (crc >> 1);
endfunction

// One-byte CRC step: XOR byte into low bits, then 8 bit-steps
function Bit#(32) crcByte(Bit#(32) crc, Bit#(8) bval, Bit#(32) poly);
    Bit#(32) c = crc ^ zeroExtend(bval);
    for (Integer i = 0; i < 8; i = i + 1)
        c = crcBit(c, poly);
    return c;
endfunction

// CRC32 (IEEE 802.3) for 8-byte input
function Bit#(32) crc32(Bit#(64) data);
    Bit#(32) crc = 32'hFFFFFFFF;
    for (Integer i = 0; i < 8; i = i + 1)
        crc = crcByte(crc, data[i * 8 + 7 : i * 8], 32'hEDB88320);
    return crc ^ 32'hFFFFFFFF;
endfunction

// CRC32C (Castagnoli) for 8-byte input
function Bit#(32) crc32c(Bit#(64) data);
    Bit#(32) crc = 32'hFFFFFFFF;
    for (Integer i = 0; i < 8; i = i + 1)
        crc = crcByte(crc, data[i * 8 + 7 : i * 8], 32'h82F63B78);
    return crc ^ 32'hFFFFFFFF;
endfunction

endpackage
