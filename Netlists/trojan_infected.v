// ============================================================
//  trojan_infected.v
//  AES S-Box with embedded Hardware Trojan
//
//  TROJAN STRUCTURE:
//    - Trigger: rare condition on low-fanout net (trojan_trigger)
//    - Payload: XOR flips output bit when triggered (trojan_payload)
// ============================================================

module aes_sbox_trojan (
    input  clk,
    input  rst,
    input  [7:0] data_in,
    output [7:0] data_out
);

    // Primary I/O wires
    wire [7:0] sbox_out;
    wire [7:0] masked;

    // ── Normal circuit ──────────────────────────────────────
    and  g1  (w1,  data_in[0], data_in[1]);
    and  g2  (w2,  data_in[2], data_in[3]);
    and  g3  (w3,  data_in[4], data_in[5]);
    and  g4  (w4,  data_in[6], data_in[7]);
    or   g5  (w5,  w1, w2);
    or   g6  (w6,  w3, w4);
    xor  g7  (w7,  w5, w6);
    not  g8  (w8,  w7);
    buf  g9  (sbox_out[0], w8);
    buf  g10 (sbox_out[1], w7);
    buf  g11 (sbox_out[2], w5);
    buf  g12 (sbox_out[3], w6);
    buf  g13 (sbox_out[4], w1);
    buf  g14 (sbox_out[5], w2);
    buf  g15 (sbox_out[6], w3);
    buf  g16 (sbox_out[7], w4);

    // ── TROJAN: Trigger Logic ────────────────────────────────
    // Activates only when data_in == 8'b10110100 (rare pattern)
    not  tg1 (t_n0,  data_in[0]);          // data_in[0] == 0
    not  tg2 (t_n2,  data_in[2]);          // data_in[2] == 0
    not  tg3 (t_n5,  data_in[5]);          // data_in[5] == 0
    not  tg4 (t_n7,  data_in[7]);          // data_in[7] == 0
    and  tg5 (trojan_trigger, t_n0, data_in[1], t_n2,
                              data_in[3],  data_in[4], t_n5,
                              data_in[6],  t_n7);    // fanout=1 → suspicious!

    // ── TROJAN: Payload Logic ────────────────────────────────
    // Flips bit 0 of output when triggered
    xor  tp1 (trojan_payload, trojan_trigger, sbox_out[0]);  // fanout=1

    // Mux: selects payload when triggered, normal otherwise
    mux  tp2 (masked[0], sbox_out[0], trojan_payload, trojan_trigger);
    buf  tp3 (masked[1], sbox_out[1]);
    buf  tp4 (masked[2], sbox_out[2]);
    buf  tp5 (masked[3], sbox_out[3]);
    buf  tp6 (masked[4], sbox_out[4]);
    buf  tp7 (masked[5], sbox_out[5]);
    buf  tp8 (masked[6], sbox_out[6]);
    buf  tp9 (masked[7], sbox_out[7]);

    // ── Optional: Isolated latch (no reset) ─────────────────
    latch iso1 (iso_q, trojan_trigger, clk);   // no reset → suspicious

    // Output
    buf  out0 (data_out[0], masked[0]);
    buf  out1 (data_out[1], masked[1]);
    buf  out2 (data_out[2], masked[2]);
    buf  out3 (data_out[3], masked[3]);
    buf  out4 (data_out[4], masked[4]);
    buf  out5 (data_out[5], masked[5]);
    buf  out6 (data_out[6], masked[6]);
    buf  out7 (data_out[7], masked[7]);

endmodule
