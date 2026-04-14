package AnchorExtractor;

import FIFOF::*;
import Vector::*;
import LongEngineTypes::*;

// Extracts 8-byte anchors from 57 positions in a 64-byte packet.
// Position i: payload[i*8 +: 64] (bytes i..i+7), for i in 0..56.
// Lane i is valid iff (i + 8) <= len.

interface AnchorExtractorIfc;
    method Action enqPacket(Payload payload, PayloadLen len);
    interface Vector#(NumLanes, FIFOF#(LaneData)) pipes;
endinterface

module mkAnchorExtractor(AnchorExtractorIfc);
    Vector#(NumLanes, FIFOF#(LaneData)) pipeArray <- replicateM(mkFIFOF);

    function ValidMaskBits generateValidMask(PayloadLen len);
        ValidMaskBits mask = 0;
        for (Integer i = 0; i < valueOf(NumLanes); i = i + 1) begin
            if (fromInteger(i + 8) <= len)
                mask[i] = 1;
        end
        return mask;
    endfunction

    function LaneData extractSlice(Payload payload, Integer idx);
        return truncate(payload >> fromInteger(idx * 8));
    endfunction

    method Action enqPacket(Payload payload, PayloadLen len);
        ValidMaskBits vmb = generateValidMask(len);
        for (Integer i = 0; i < valueOf(NumLanes); i = i + 1) begin
            if (vmb[i] == 1)
                pipeArray[i].enq(extractSlice(payload, i));
        end
    endmethod

    interface pipes = pipeArray;
endmodule

endpackage
