// https://gist.github.com/tothi/d5588638b067517400312427281042a8
// Frida dumb antiroot check bypass on LineageOS for the
// com.vasco.digipass root checker in hu.khb banking app
//
// run with: frida -U -f hu.khb -l antirootbypass.js --no-pause

// root file existence check
Interceptor.attach(Module.findExportByName(null, 'access'), {
    onEnter: function (args) {
	this._pathname = args[0].readCString();
	this._mode = args[1];
    },
    onLeave: function (retval) {
	var patch = 0;
	if (this._pathname == "/system/bin/su") {
	    retval.replace(-1);
	    patch = 1;
	}
	if (this._pathname == "/system/bin/../bin/su") {
	    retval.replace(-1);
	    patch = 1;
	}
	console.log(JSON.stringify({
	    patch: patch,
	    function: "access",
	    result: retval,
	    pathname: this._pathname,
	    mode: this._mode
	}));
    }
});

Interceptor.attach(Module.findExportByName(null, 'faccessat'), {
    onEnter: function (args) {
	this._pathname = args[1].readCString();
	this._mode = args[2];
    },
    onLeave: function (retval) {
	var patch = 0;
	if (this._pathname == "/system/bin/su") {
	    retval.replace(-1);
	    patch = 1;
	}
	if (this._pathname == "/system/bin/../bin/su") {
	    retval.replace(-1);
	    patch = 1;
	}

	// ugly hack for attaching Java hooks immediately _after_ start
	// it does not work unfortunately by simply attaching at spawn time
	if (this._pathname == "/system/framework") {
	    patch = 2;
	    Java.perform(function() {

		// string decryptor hook for debugging
		var u = Java.use("com.vasco.digipass.sdk.utils.utilities.UtilitiesSDK");
		u.xsVUhL4q6C.overload('java.lang.String').implementation = function(s) {
		    var x = this.xsVUhL4q6C.call(this, s);
		    console.log("########### " + x);
		    return x;
		};

		// system property reader/debugger/patcher
		var SystemProperties = Java.use('android.os.SystemProperties');
		var get = SystemProperties.get.overload('java.lang.String');
		
		get.implementation = function(name) {
		    var val;
		    if (name == "ro.build.display.id") {
			val = "RQ3A.210705.001 test-keys";
		    } else if (name == "ro.build.user") {
			val = "OnePlus";
		    } else if (name == "ro.build.host") {
			val = "ubuntu-10";
		    } else if (name == "ro.build.flavor") {
			val = "OnePlus8-user";
		    } else {
			val = this.get.call(this, name);
		    }
		    send("++++++++ Property " + name + ":" + val);
		    return val;
		};
		
	    });
	}
	
	console.log(JSON.stringify({
	    patch: patch,
	    function: "faccessat",
	    result: retval,
	    pathname: this._pathname,
	    mode: this._mode
	}));
    }
});

// not used for patching, just for debugging purposes
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function (args) {
	this._pathname = args[0].readCString();
	this._flags = args[1];
    },
    onLeave: function (retval) {
	console.log(JSON.stringify({
	    function: "open",
	    result: retval,
	    pathname: this._pathname,
	    flags: this._flags
	}));
    }
});
