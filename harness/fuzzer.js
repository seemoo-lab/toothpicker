// This is the main Fuzzer class that needs to be instatiated by every 
// project specific (i.e., specialized harness) script.

class Fuzzer {
    constructor() {
        this.payload_buf = Memory.alloc(0x10000);
        this.target_function = null;
        
        this.stalker_events = [];
        this.maps = this._make_maps();
        this.gc_cnt = 0;
    }

    _make_maps() {
        var maps = Process.enumerateModulesSync();
        var i = 0;
        // We need to add the module id
        maps.map(function(o) { o.id = i++; });
        // .. and the module end point
        maps.map(function(o) { o.end = o.base.add(o.size); });

        var module_ids = {};
        maps.map(function (e) {
            module_ids[e.path] = {id: e.id, start: e.base};
        });

        return maps;
    }

    prePrepare() {}

    postPrepare() {}

    isReady() { return true; }

    processPayload (payload) { 
        if (payload.length > 1024)
            payload = payload.slice(0, 1024);
        return payload.slice;
    }

    getPid() {
        return Process.id;
    }

    setFunction(fn) {
        this.target_function = fn;
    }

    getMaps() {
        return this.maps
    }

    fuzzInternal(payload) {
        this.fuzz(payload)
        return this.stalker_events;
    }

    prepare() {
        var self = this;
        if (!self.target_function) {
            console.log("Set the function before calling prepare()");
            return;
        }
        // call the user defined pre prepare function
        self.prePrepare();

        Interceptor.attach(self.target_function, {
             onEnter: function (args) {
                self.stalker_events = undefined;
                Stalker.follow({
                  events: {
                      call: false,
                      ret: false,
                      exec: false,
                      block: false,
                      compile: true,
                  },
                  onReceive: function (events) {
                      var bbs = Stalker.parse(events,
                          {stringify: false, annotate: false});
                      if(self.stalker_events != undefined) {
                          // warning("onReceive: Got another stalker event!")
                      }
                      self.stalker_events = bbs;
                  },
                });
            },
            onLeave: function (retval) {
                Stalker.unfollow()
                Stalker.flush();
                if(self.gc_cnt % 100 == 0){
                    Stalker.garbageCollect();
                }
                self.gc_cnt++;
            }
        });

    }

    getCoverage() {
        return this.stalker_events;
    }

    // This is required for frida to pick up the class' methods...
    makeExports() {
        var self = this;
        return {
            isReady: () => {return self.isReady()},
            getCoverage: () => {return self.getCoverage()},
            prepare: ()=>{return self.prepare()},
            postPrepare: ()=>{return self.postPrepare()},
            processPayload: (payload)=>{return self.processPayload(payload)},
            getMaps: () => {return self.getMaps()},
            setFunction: (fn) => {return self.setFunction(fn)},
            getPid: () => {return self.getPid()},
            fuzzInternal: (payload) => {return self.fuzzInternal(payload)},
        }
    }
}

exports.Fuzzer = Fuzzer;
