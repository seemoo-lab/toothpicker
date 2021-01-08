// ToothFlipper: flip single bits/bytes in a Bluetooth connections.
//
// We're using OI_HCIIfc_DataReceived for fuzzing bluetoothd this
// time instead of ToothPicker's ACL handlers. This means that we
// also cover SCO (speech) and HCI (config) stuff. And it's more
// stateful. Enjoy fuzzing like some monkey and listening to bad
// sound quality music...


var base = Module.getBaseAddress('bluetoothd');

// Functions contain function name strings, easy to determine.
var OI_HCIIfc_DataReceived = base.add(0xee9f0);  // iOS 14.3, iPhone 8 (18C66)
// var OI_HCIIfc_DataReceived = base.add(0x108e04);  // iOS 13.5, iPhone SE2

// Verbose output
var debug = false;

// "Randomness"
var seed1 = 13372342;  // use this for payload offsets
var seed2 = 12312312;  // use this for payload values

// Likeliness of corruptions
var l_corrupt_bit = 7;
var l_corrupt_byte = 11;
var l_corrupt_4byte = 23;
//var l_insert_byte = 9;

// Do not corrupt from the very beginning.
// Later corruptions might hit other parts in the protocol.
var start_corruptions = 3;

// Statistics
var s_corrupt_bit = 0;
var s_corrupt_byte = 0;
var s_corrupt_4byte = 0;
//var s_insert_byte = 0;
var frames_in_total = 0;

// Fuzzing in output direction only fuzzes the crappy Broadcom chip,
// can be done via OI_HciIfc_CopyPayload, but makes it super unstable
// because there is an overflow in the UART packet processing m)
//var frames_out_total = 0;

// For complex operations that insert bytes we need
// a separate buffer.
//var payload_buffer = Memory.alloc(0x4000);

// Change a byte every now and then in a packet but not too often.
// Very pseudo-random, definitely no good fuzzer, just for testing.
function fuzz_input(acl, len) {

    // Keep track of total packets before fuzzing
    frames_in_total += 1;

    // Change seed slightly even if we didn't get any seed input
    seed1 += 1;
    seed2 += 1;

    // Skip initial packets
    if (start_corruptions > frames_in_total) {
        console.log(frames_in_total + " frames received, waiting until " + start_corruptions + "...");
        return;
    }

    // Read memory as it is
    //var d=acl.readByteArray(len);

    // Super simple mutations with redundant code...
    // TODO feel free to adjust this :)


    // Fuzz at this offset
    var off = seed1 % len;

    if ((seed1 % l_corrupt_bit) == 0) {
        s_corrupt_bit += 1;
        var original_byte = acl.add(off).readU8();
        original_byte = original_byte ^ (0x1 << (seed2 % 8));
        acl.add(off).writeByteArray([original_byte]);

        var f=acl.readByteArray(len);
        send('data', f);   // also send the payload (but might crash already)
        if (debug) {
            console.log('  ! corrupted 1 bit');
        }
    }
    if ((seed1 % l_corrupt_byte) == 0) {
        s_corrupt_byte += 1;
        acl.add(off).writeByteArray([seed2 % 0xff]);

        var f=acl.readByteArray(len);
        send('data', f);   // also send the payload (but might crash already)
        if (debug) {
            console.log('  ! corrupted 1 byte');
        }
    }
    if ((seed1 % l_corrupt_4byte) == 0) {
        s_corrupt_4byte += 1;
        acl.add(off-3).writeByteArray([seed2 & 0xff, (seed2 & 0xff00) >> 8, (seed2 & 0xff0000) >> 16, (seed2 & 0xff000000) >> 24]);

        var f=acl.readByteArray(len);
        send('data', f);   // also send the payload (but might crash already)
        if (debug) {
            console.log('  ! corrupted 4 bytes');
            console.log(f);
        }
    }

    console.log('packets in: ' + frames_in_total + ', flipped 1b ' + s_corrupt_bit + ' | 1B ' + s_corrupt_byte + ' | 4B ' + s_corrupt_4byte);
}


// *** Receiving direction ***
// OI_HCIIfc_DataReceived gets all packet types. It then calls
// HCI/SCO/ACL in the next step, and with one function in between
// ends up in OI_HCIIfc_AclPacketReceived (aka acl_recv).
// During music streaming, we usually don't receive ACL, except for
// events triggered by the user such as pressing pause/play on the
// headset buttons.

Interceptor.attach(OI_HCIIfc_DataReceived, {
    onEnter: function(args) {

        var h4t = parseInt(this.context.x0);  // ACL/SCO/HCI
        var acl = this.context.x1;
        var len = parseInt(this.context.x2);
        if (debug) {
            console.log("OI_HCIIfc_DataReceived, len " + len + ", type " + h4t);
            console.log(dst.readByteArray(len));
        }

        // Uncomment this to filter for a specific type:
        //  HCI: 0x01 (command, invalid in this direction)
        //  ACL: 0x02
        //  SCO: 0x03
        //  HCI: 0x04 (events + BLE data, this is valid)
        //  DIAG: 0x07 (should be disabled here)
        //
        // My Bose QC35II and AirPods both seem to use BLE Audio on iOS 14.3 :D
        // This is type 4... only the play/pause are ACL like a keyboard.
        //
        // Fixme The fuzzer currently doesn't log the H4 type.
        //if (h4t == 4) {
            fuzz_input(acl, len);
        //}
    }
});


// Make exports accessible via Python
rpc.exports = {
    // Export for seed input.
    seed: function (off, val) {
        seed1 = parseInt(off);
        seed2 = parseInt(val);
        if (debug) {
            console.log("Got new seed.");
            console.log(seed1);
            console.log(seed2);
        }
    }
};
