const fuzzer = require("../../harness/fuzzer.js");
const bluetoothd = require("../../harness/bluetoothd.js");

const base = Module.getBaseAddress("bluetoothd");

class MPFuzzer extends fuzzer.Fuzzer {
    constructor() {
        super()
        // Set the targeted function that is fuzzed and stalked.
        this.setFunction(base.add(bluetoothd.symbols.ACL_reception_handler));

        this.acl_reception_handler = new NativeFunction(
            base.add(bluetoothd.symbols.ACL_reception_handler),
            "void", ["int64", "int64", "pointer"], {
        });
    }
    // The pre pepare function is called once the script is loaded into the target process,
    // the post prepare function is called once the is_ready function returns true. This
    // allows different preparation operations before a ready state.
    prePrepare() {
        this.handle = bluetoothd.setupFakeACLConnection();

        // send a MP ping to increase l2cap mtu
        Memory.writeByteArray(this.payload_buf, [0x03, 0x00, 0x30, 0x00, 0xF0, 0x00, 0x00]);
        this.acl_reception_handler(0x11 + (0x20<<8), 7, ptr(this.payload_buf));
    }

    processPayload (payload) { 
        var payload_array = [];
        for(var i = 0; i < payload.length; i+=2) {
            payload_array.push(parseInt(payload.substring(i, i + 2), 16));
        }

        var handle = parseInt(0x11 + (0x20 << 8));
        var length = payload_array.length - 4;

        // set MP fixed channel 
        payload_array[6] = 0x30;
        payload_array[7] = 0x00;

        // fix L2CAP length
        var l2cap_len = payload_array.length - 8;
        payload_array[4] = l2cap_len & 0xff;
        payload_array[5] = (l2cap_len >> 8) & 0xff;

        // overwrite handle
        payload_array[0] = 0x11;
        payload_array[1] = 0x20;

        payload = ""
        for (var i = 0; i < payload_array.length; i++) {
            var _byte = parseInt(payload_array[i]).toString(16)
            payload += _byte.length == 2 ? _byte : "0" + _byte
        }
        return payload
    }

    fuzz(payload) {
        var payload_array = [];
        for(var i = 0; i < payload.length; i+=2) {
            payload_array.push(parseInt(payload.substring(i, i + 2), 16));
        }
        var length = payload_array.length - 4;
        var handle = parseInt(0x11 + (0x20 << 8));

        Memory.writeByteArray(this.payload_buf, payload_array);
        this.acl_reception_handler(handle, length, ptr(this.payload_buf).add(4));
    }

}

var f = new MPFuzzer();
rpc.exports = f.makeExports()
rpc.exports.f = MPFuzzer;
