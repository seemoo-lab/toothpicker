var base = Module.getBaseAddress("bluetoothd");

// iOS 13.3 bluetoothd symbols
// var is_internal_build = base.add(0x57134);
// var debug_print = base.add(0x151118);
// var DEBUG_PRINT_STRBUFFER = base.add(0x553b20);

// iOS 13.5 Beta 4 bluetoothd symbols
var is_internal_build = base.add(0x07f428);
var debug_print = base.add(0x17b69c);
var DEBUG_PRINT_STRBUFFER = base.add(0x05d8ae0);

// enable logging
Interceptor.attach(debug_print,{
    onLeave: function() {
        // this string buffer is a global buffer that is the target of some
        // sort of sprintf function within debug_print, so we just print 
        // this here
        console.log(Memory.readCString(DEBUG_PRINT_STRBUFFER));
    }
});

// pretend to be an internal build for more output
Interceptor.replace(is_internal_build, new NativeCallback(function() {return 1;}, "int", [])) 
