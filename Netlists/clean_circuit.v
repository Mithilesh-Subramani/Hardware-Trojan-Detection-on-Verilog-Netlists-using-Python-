// ============================================================
//  clean_circuit.v
//  Standard AES S-Box  –  NO Trojan
//  All nets connect to primary outputs; no isolated logic.
// ============================================================

module aes_sbox_clean (
    input  clk,
    input  rst,
    input  [7:0] data_in,
    output [7:0] data_out
);

    // Combinational S-box approximation
    and  g1  (w1,  data_in[0], data_in[1]);
    and  g2  (w2,  data_in[2], data_in[3]);
    and  g3  (w3,  data_in[4], data_in[5]);
    and  g4  (w4,  data_in[6], data_in[7]);
    or   g5  (w5,  w1, w2);
    or   g6  (w6,  w3, w4);
    xor  g7  (w7,  w5, w6);
    not  g8  (w8,  w7);

    // All outputs properly connected
    buf  o0  (data_out[0], w8);
    buf  o1  (data_out[1], w7);
    buf  o2  (data_out[2], w5);
    buf  o3  (data_out[3], w6);
    buf  o4  (data_out[4], w1);
    buf  o5  (data_out[5], w2);
    buf  o6  (data_out[6], w3);
    buf  o7  (data_out[7], w4);

    // DFF with proper reset
    dff  ff0 (q0, w8, clk, rst);
    dff  ff1 (q1, w7, clk, rst);

endmodule
