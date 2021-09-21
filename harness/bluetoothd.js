var symbol_library = require("./symbols.js");

var base = Module.getBaseAddress("bluetoothd");

// TODO: select iOS version from symbols file (symbols.js)
var symbols = symbol_library.symbols.symbols_ios_14_4_iphone8;

// Allocate global buffers used during fuzzing
var bd_addr_native = Memory.alloc(8);
var recv_buf = Memory.alloc(1024);

// Javascript is usually asynchronous, but we need a synchronous sleep for
// certain cases ¯\_(ツ)_/¯
function sleep(ms) {
    const start = new Date().getTime(), expire = start + ms;
    while (new Date().getTime() < expire) { }

}

// This function prints the hci connection structure
function dump_hci_handle(hci_handle) {    
    hci_handle = ptr(hci_handle)
    console.log("hci_handle: " + hci_handle.toString());
    console.log("\thandle_value: " + Memory.readShort(hci_handle));
    console.log("\thandle_type: " + Memory.readU8(hci_handle.add(2)));
    console.log("\tconnection_num: " + Memory.readInt(hci_handle.add(4)));
    console.log("\tnext: " + Memory.readPointer(hci_handle.add(0x20)));
    console.log("\tbd_addr: " + Memory.readByteArray(hci_handle.add(0x28), 6));
    console.log("\thandle_state: " + Memory.readU8(hci_handle.add(0x28+6)));
    console.log("\tsome_struct_for_other_handle: " + Memory.readPointer(hci_handle.add(0x38)));
    console.log("\tfield_0x70: " + Memory.readPointer(hci_handle.add(0x70)));
    console.log("\tfield_0x78: " + Memory.readPointer(hci_handle.add(0x78)));
    console.log("\trefcount: " + Memory.readInt(hci_handle.add(0x8c)));
    console.log("\tsome_struct_for_ACL_handle: " + Memory.readPointer(hci_handle.add(0x98)));
    console.log("\tsome_struct_for_LE_handle: " + Memory.readPointer(hci_handle.add(0xb0)));
    console.log("\tsome_other_struct_for_LE: " + Memory.readPointer(hci_handle.add(0xd0)));
};

function handle_set_field0(handle, val) {
    Memory.writeShort(ptr(handle), val);
}

function handle_set_refcount(handle, val) {
    Memory.writeInt(ptr(handle).add(0x8c), val);
}

function handle_set_state(handle, val) {
    Memory.writeU8(ptr(handle).add(0x28+6), val);
}

function handle_set_handle_val(handle, val) {
    Memory.writeShort(ptr(handle), val);
}

function createDynamicL2CAPChannel(handle, PSM) {
    var fn_addr = base.add(symbols.OI_LP_ConnectionAdded);
    var _OI_LP_ConnectionAdded = new NativeFunction(fn_addr.sign(), "void", ["pointer", "int",
        "int", "int", "int"]);

    // Unfortunately, we don't get the allocated CID back when allocating the channel, so 
    // we're doing an extremely hacky hack to get it. In the OI_LP_ConnectionAdded function
    // there is a print statement which prints the PSM and the allocated CID. At this stage,
    // the L2CAP channel structure is in x0, so we can extract the CID from there. We intercept
    // this address and get the CID from there. At the end of this function we just wait until 
    // we have that value. Ugh...
    var cid = null;
    var listener = Interceptor.attach(base.add(symbols.OI_LP_ConnectionAdded_cid_str), function () {
        if (cid == null) {
            cid = Memory.readShort(this.context.x0.add(4))
        } 
    });
    var x0 = handle;        // this is our connection handle pointer
    var x1 = PSM;           // the PSM of the protocol we want to connect to
    var x2 = 0x40;
    var x3 = 0x1;
    var x4 = 0x11;          // this looks like it's supposed to be the handle value
    _OI_LP_ConnectionAdded(x0, x1, x2, x3, x4);

    // Wait until we received the CID value
    while(cid == null) {
        sleep(100);
    }

    // detach the interceptor again
    listener.detach();
    return cid;
}

function allocateACLConnection(bd_addr, handle_status) {
    var fn_addr = base.add(symbols.allocateACLConnection);

    var _allocateACLConnection = new NativeFunction(fn_addr.sign(), "pointer", ["pointer", "char"]);

    bd_addr_native.writeByteArray(bd_addr);

    var handle = _allocateACLConnection(bd_addr_native, handle_status);
    if (handle == 0x00) {
        console.error("Cannot allocate handle. Handle with this BD addr probably already exists");
    }
    return handle
};

function allocateLEConnection(handle_val, bd_addr_state_buf) {
    // These values have been observed by hooking the create_connection
    // function and creating a real BLE connection (with an android phone
    // running nRF connect)
    var x0 = 0x0;
    var x1 = handle_val;
    var x2 = 0x1;
    var x4 = 0x24;
    var x5 = 0x0;
    var x6 = 0x1f4;
    var x7 = 0x1;

    var _create_connection = new NativeFunction(base.add(symbols.create_connection).sign(),
        "void", ["long", "long", "int", "pointer", "long", "int16", "int16", "int8"]);
    var _hci_handle_exists = new NativeFunction(base.add(symbols.hci_handle_exists).sign(),
        "pointer", ["int"]);
    var _ReadRemoteVersionInformationCB = new NativeFunction(base.add(symbols.ReadRemoteVersionInformationCB).sign(),
        "void", ["long", "pointer", "long", "long", "long", "pointer", "long", "long"]);

    // not actually just the bd_addr, but we use this buffer anyways
    bd_addr_native.writeByteArray(bd_addr_state_buf);

    _create_connection(x0, x1, x2, bd_addr_native, x4, x5, x6, x7);

    console.log(handle_val);

    // now that we have the handle we need to fetch the connection struct
    var connection = _hci_handle_exists(handle_val);
    console.log(connection);
    if (connection == ptr(0x00)) {
        console.error("No connection for this handle, something in BLE setup went wrong");
    }

    sleep(1);

    // lastly, fake a ReadRemoteVersionInformation event by calling its callback
    // again, the values are taken from connecting the android device with nRF connect
    _ReadRemoteVersionInformationCB(0x0, connection, 0x8, 0x46, 0x1130, ptr(0x00), 0x0, 0x403)

    sleep(1);

    return connection
}

function OI_SignalMan_Recv(handle, data, length) {
    var fn_addr = base.add(symbols.OI_SignalMan_Recv);

    var _OI_SignalMan_Recv = new NativeFunction(fn_addr.sign(), "void", ["pointer", "pointer", "int64"]);

    data = new Uint8Array(data);
    Memory.writeByteArray(recv_buf, data);
    _OI_SignalMan_Recv(ptr(handle), ptr(recv_buf), length);
};

function wrap_l2cap_reception_handler(handler_ptr, handle, data, length) {
    var fn_addr = base.add(handler_ptr);

    var _fn = new NativeFunction(fn_addr.sign(), "void", ["pointer", "pointer", "int64"]);
    
    data = new Uint8Array(data);
    Memory.writeByteArray(recv_buf, data);
    _fn(ptr(handle), ptr(recv_buf), length);
}

function overwriteProblematicFunctions() {
    // Replace timeout function registering and not let it register
    // the startSecurityPolicyEnforcement function
    var startSecurityPolicyEnforcement_addr = base.add(symbols.startSecurityPolicyEnforcement);
    var register_timeout_addr = base.add(symbols.registerTimeout);

    var orig_register_timeout = new NativeFunction(register_timeout_addr.sign(), "int64", ["pointer", "pointer", "pointer", "pointer"]);

    Interceptor.replace(register_timeout_addr, new NativeCallback(function(fn, b, c, d) {
        if(parseInt(fn,16) == parseInt(startSecurityPolicyEnforcement_addr,16)) {
            return 0;
        }
        return orig_register_timeout(fn, b, c, d);
    }, "int64", ["pointer", "pointer", "pointer", "pointer"]));

    if (symbols.enforceLinkPolicy)
        Interceptor.replace(base.add(symbols.enforceLinkPolicy), new NativeCallback(function() {}, "void", []));

    if (symbols.ble_adv_stuff)
        Interceptor.replace(base.add(symbols.ble_adv_stuff), new NativeCallback(function() {}, "void", []));

    if(symbols.coreDumpPacketCounter)
        Interceptor.replace(base.add(symbols.coreDumpPacketCounter), new NativeCallback(function() {}, "void", []));
}

function setupFakeLEConnection() {
    // Currently we don't have this symbol for every version
    if (symbols.is_internal_build) {
        var is_internal_build = base.add(symbols.is_internal_build);
        // pretend to be an internal build for more output
        Interceptor.replace(is_internal_build, new NativeCallback(function() {return 1;}, "int", []))
    }

    // First byte (probably) indicates the type of address, last byte seems to be the
    // status of the connection. In between is the BD addr
    allocateLEConnection(0x46, [0xf1, 0x63, 0x62, 0xfc, 0x1d, 0x90, 0xcd, 0xf1]);

    // Overwrite the function that disconnects ACL handles
    Interceptor.replace(base.add(symbols.bt_forceDisconnect), 
        new NativeCallback(function(a, b) {
            return 1;
        }, "int", ["pointer", "pointer"])
    );

    // Overwrite HCI disconnect function
    Interceptor.replace(base.add(symbols.OI_HCI_ReleaseConnection),
        new NativeCallback(function(a, b) {
            return;
        }, "void", ["pointer"])
    );

    // Overwrite GATT disconnection callback
    Interceptor.replace(base.add(symbols._GATT_LE_DisconnectedCB),
        new NativeCallback(function(a, b) {
            return;
        }, "void", ["pointer", "pointer"])
    );

    Interceptor.replace(base.add(symbols.LE_ReadRemoteVersionInformationComplete),
        new NativeCallback(function(a, b) {
            return;
        }, "void", ["pointer", "pointer"])
    );

    overwriteProblematicFunctions();
}

function setupFakeACLConnection() {
    var handle = allocateACLConnection([0xf4, 0xaf, 0xe7, 0x15, 0x51, 0xbc], 1);
    
    // edit the handle object a bit
    handle_set_field0(handle, 11);
    // set the refcount to some number to prevent it from getting freed/disconnected
    handle_set_refcount(handle, 15);
    handle_set_state(handle, 0);
    // set handle value to be used in ACL data
    handle_set_handle_val(handle, 0x11);

    dump_hci_handle(handle);

    // overwrite the function that disconnects ACL handles
    Interceptor.replace(base.add(symbols.bt_forceDisconnect), 
        new NativeCallback(function(a, b) {
            return 1;
        }, "int", ["pointer", "pointer"])
    );

    // Sometimes some HCI stuff happens... which then leads to a free(0) and this
    // leads to an abort which would not happen with a real connection.
    // However, overwriting slightly changes the fuzzing behavior and can lead to
    // false positives...
    if (symbols.btstack_free) {
        var orig_fn = new NativeFunction(base.add(symbols.btstack_free).sign(), "void", ["pointer"]);
        Interceptor.replace(base.add(symbols.btstack_free),
            new NativeCallback(function(a) {
                return;
                if (a == 0)
                    return;
                orig_fn(a);
            }, "void", ["pointer"])
        );
    }

    overwriteProblematicFunctions();

    return handle;
}


exports.base = base;
exports.OI_SignalMan_Recv = OI_SignalMan_Recv;
exports.dump_hci_handle = dump_hci_handle;
exports.allocateACLConnection = allocateACLConnection;
exports.wrap_l2cap_reception_handler = wrap_l2cap_reception_handler;
exports.setupFakeACLConnection= setupFakeACLConnection;
exports.setupFakeLEConnection = setupFakeLEConnection;
exports.createDynamicL2CAPChannel = createDynamicL2CAPChannel;
exports.symbols = symbols;
