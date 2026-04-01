`timescale 1ns/1ps

module tb_aes128_core;

    reg         clk;
    reg         rst;
    reg         start;
    reg [127:0] key;
    reg [127:0] plaintext;
    wire [127:0] ciphertext;
    wire        busy;
    wire        done;

    aes128_core dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .key(key),
        .plaintext(plaintext),
        .ciphertext(ciphertext),
        .busy(busy),
        .done(done)
    );

    always #5 clk = ~clk;

    initial begin
        clk = 1'b0;
        rst = 1'b1;
        start = 1'b0;

        key       = 128'h000102030405060708090a0b0c0d0e0f;
        plaintext = 128'h00112233445566778899aabbccddeeff;

        /*
        EXPECTED: 69c4e0d86a7b0430d8cdb78070b4c55a
        */

        #20;
        rst = 1'b0;

        #10;
        start = 1'b1;

        #10;
        start = 1'b0;

        wait(done == 1'b1);

        $display("Key        = %032h", key);
        $display("Plaintext  = %032h", plaintext);
        $display("Ciphertext = %032h", ciphertext);

        if (ciphertext == 128'h69c4e0d86a7b0430d8cdb78070b4c55a)
            $display("PASS: AES-128 test vector matched.");
        else
            $display("FAIL: expected 69c4e0d86a7b0430d8cdb78070b4c55a");

        #20;
        $finish;
    end

endmodule