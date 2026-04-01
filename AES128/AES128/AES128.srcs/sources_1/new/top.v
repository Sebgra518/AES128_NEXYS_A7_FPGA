`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: N/A
// Engineer: Sebastian Graciano
// 
// Create Date: 03/31/2026 06:47:29 PM
// Design Name: 
// Module Name: top
// Project Name: AES128
// Target Devices: Raspbery Pi 5
// Tool Versions: Vivado 2025.1
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////
module top (
    input wire clk,        // 100 MHz clock
    input wire reset,        // reset (active high)
    output reg led         // LED output
);

    reg [26:0] counter;    // 27-bit counter

    always @(posedge clk) begin
        if (reset) begin
            counter <= 0;
            led <= 0;
        end else begin
            counter <= counter + 1;

            // Toggle LED when counter overflows
            if (counter == 0)
                led <= ~led;
        end
    end

endmodule