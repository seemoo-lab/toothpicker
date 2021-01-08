const fuzzer = require("../../harness/fuzzer.js");
const bluetoothd = require("../../harness/bluetoothd.js");

// const f = new fuzzer.Fuzzer();
const base = Module.getBaseAddress("bluetoothd");

class MPFuzzer extends fuzzer.Fuzzer {
    constructor() {
        super()
        // Set the targeted function that is fuzzed and stalked.
        this.setFunction(base.add(bluetoothd.symbols.ACL_reception_handler));

        this.acl_reception_handler = new NativeFunction(
            base.add(bluetoothd.symbols.ACL_reception_handler),
            "void", ["int64", "int64", "pointer"], {
                //exceptions: "propagate",
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
            var val = payload.substring(i, i + 2);
            var intval = parseInt(val, 16);
            payload_array.push(intval);
        }

        payload_array[0] = 0x11;
        payload_array[1] = 0x20;

        // don't trigger L2CAP group deref
        var cid_byte = payload_array[6]
        if(cid_byte == 0x02 || cid_byte == 0x30 || cid_byte == 0x04) {
            payload_array[6] = 0x01;
        }
        if (payload_array[6] == 0x01 && payload_array.length > 23 && payload_array[22] == 0x04 && payload_array[23] == 0xf3) {
            payload_array[6] = 0x03;
        }

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
        var length = parseInt(payload[2] + (payload[3]<<8));
        var handle = parseInt(0x11 + (0x20 << 8));


        Memory.writeByteArray(this.payload_buf, payload_array);
        this.acl_reception_handler(handle, length, ptr(this.payload_buf).add(4));
    }

}

var f = new MPFuzzer();
rpc.exports = f.makeExports()
rpc.exports.f = MPFuzzer;
