
本文内容主要收集自网络。

# frida版 通过dexfile指针 获得 类列表
```javascript
Java.perform(function(){
 
    var strptr=beg.add(0x44);
    strptr=strptr.readU32();
     len=Memory.readU32(beg.add(0x60));
      c = new Array(len);
    var hj=0;
    var classptr=beg.add(0x64);
    var everyclass=null;
    var everystr=null;
    var strp=null;
//console.log(len);

     for(hj=0;hj<=len;hj++){
c[hj]=0;
 everystr=beg.add(classptr.readU32()+0x20*hj).readU32();

 everystr=everystr*4;
  //strp=strptr.add(everystr);
  //console.log(strptr);
  strp=beg.add(strptr+everystr);
strp=(strp.readU32())*4;
strp=beg.add(strp+0x70);
strp=strp.readU32();
//console.log(beg.add(strp+1).readCString());
//strp=beg.add(strp);
b[hj]=beg.add(strp+2).readCString().replace(/\//g,".")
b[hj]=b[hj].replace(/;/g,"");
// strp=strp.readPointer();
// console.log(strp);
  }
//console.log(b[0]);
});
```

# frida调用 Android framework 的一个工具类进行hexdump，方便又快捷。
```js
function hexdump(bytearry,offset,length){
      // bytearray => [B
      // offset => I
      // length => I
      var HexDump = Java.use("com.android.internal.util.HexDump")
      console.log(HexDump.dumpHexString(bytearry,offset,length))
    }
```

# 虚拟机堆栈
```javascript
console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
```
相当于 Java 的 `android.util.Log.getStackTraceString(new java.lang.Throwable())` 。

# 注入 Dex
先用 sdk-build-tools 中的 dx 制作 dex , push 到手机里。
```javascript
var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
var context = currentApplication.getApplicationContext();
var pkgName = context.getPackageName();
var dexPath = "/data/local/tmp/guava.dex";
Java.openClassFile(dexPath).load();
console.log("inject " + dexPath + " to " + pkgName + " successfully!")
console.log(Java.use("com.google.common.collect.Maps"));
```

# Non-ASCII

可以先编码打印出来, 再用编码后的字符串去 hook .

```javascript
Java.perform(
    function x() {
        var targetClass = "com.example.hooktest.MainActivity";
        var hookCls = Java.use(targetClass);
        var methods = hookCls.class.getDeclaredMethods();
        for (var i in methods) {
            console.log(methods[i].toString());
            console.log(encodeURIComponent(methods[i].toString().replace(/^.*?\.([^\s\.\(\)]+)\(.*?$/, "$1")));
        }
        hookCls[decodeURIComponent("%D6%8F")]
            .implementation = function (x) {
                console.log("original call: fun(" + x + ")");
                var result = this[decodeURIComponent("%D6%8F")](900);
                return result;
            }
    }
)
```

# TracerPid
```javascript
console.log("anti_fgets");
var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
    var retval = fgets(buffer, size, fp)
    var bufstr = Memory.readUtf8String(buffer)
    if (bufstr.indexOf('TracerPid:') > -1) {
        Memory.writeUtf8String(buffer, 'TracerPid:\t0')
        // console.log('tracerpid replaced: ' + bufstr)
    }
    if (bufstr.indexOf(':' + 27042..toString(16).toUpperCase()) > -1) {
        Memory.writeUtf8String(buffer, '')
        console.log('27042 replaced: ' + bufstr)
    }
    if (bufstr.indexOf('frida') > -1) { // frida
        Memory.writeUtf8String(buffer, '')
        console.log('frida replaced: ' + bufstr)
    }

    return retval
}, 'pointer', ['pointer', 'int', 'pointer']))
```

# System.loadLibrary
```javascript

```
const SDK_INT = Java.use('android.os.Build$VERSION').SDK_INT.value
const System = Java.use('java.lang.System')
const Runtime = Java.use('java.lang.Runtime')
const VMStack = Java.use('dalvik.system.VMStack')

System.loadLibrary.implementation = function (library: string) {
    try {
        console.log('System.loadLibrary("' + library + '")')
        if (SDK_INT > 23) {
            return Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library)
        } else {
            return Runtime.getRuntime().loadLibrary(library, VMStack.getCallingClassLoader())
        }
    } catch (e) {
        console.warn(e)
    }
}

System.load.implementation = function (library: string) {
    try {
        console.log('System.load("' + library + '")')
        if (SDK_INT > 23) {
            return Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library)
        } else {
            return Runtime.getRuntime().load(library, VMStack.getCallingClassLoader())
        }
    } catch (e) {
        console.warn(e)
    }
};
```

或者
```javascript
function readStdString(str) {
    const isTiny = (str.readU8() & 1) === 0
    if (isTiny) {
        return str.add(1).readUtf8String()
    }
    return str.add(2 * Process.pointerSize).readPointer().readUtf8String()
}

var mod_art = Process.findModuleByName("libart.so")
if (mod_art) {
    for (var exp of mod_art.enumerateExports()) {
        if (exp.name.indexOf("LoadNativeLibrary") != -1) {
            console.log(exp.name, exp.address)

            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    this.pathName = readStdString(args[2])
                    console.log("[*] [LoadNativeLibrary] in  pathName =", this.pathName)
                },
                onLeave: function (retval) {
                    console.log("[*] [LoadNativeLibrary] out pathName =", this.pathName)
                }
            })

            break
        }
    }
}

var mod_dvm = Process.findModuleByName("libdvm.so")
if (mod_dvm) {
    for (var exp of mod_dvm.enumerateExports()) {
        if (exp.name.indexOf("dvmLoadNativeCode") != -1) {
            console.log(exp.name, exp.address)
            //    bool dvmLoadNativeCode(const char * pathName, void * classLoader, char ** detail)

            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    this.pathName = args[0].readUtf8String()
                    console.log("[*] [dvmLoadNativeCode] in  pathName =", this.pathName)
                },
                onLeave: function (retval) {
                    console.log("[*] [dvmLoadNativeCode] out pathName =", this.pathName)
                }
            })

            break
        }
    }
}
```

# SDK_INT
```javascript
const SDK_INT = Java.use('android.os.Build$VERSION').SDK_INT.value;
```

# dump so
```javascript
// Process.enumerateModules();
var fd = new File("/sdcard/Android/data/com.example/files/libxx.so","wb"); 
fd.write(new NativePointer(0x94300000).readByteArray(900368));fd.close(); 
```

# 找 interface 的实现
```javascript
Java.enumerateLoadedClasses(
    {
        "onMatch": function (className) {
            if (className.indexOf("com.example.hooktest.") < 0) {
                return
            }
            var hookCls = Java.use(className)
            var interFaces = hookCls.class.getGenericInterfaces()
            if (interFaces.length > 0) {
                console.log(className)
                for (var i in interFaces) {
                    console.log("\t", interFaces[i])
                }
                var methods = hookCls.class.getDeclaredMethods()
                for (var i in methods) {
                    console.log(methods[i].toString(), "\t", encodeURIComponent(methods[i].toString().replace(/^.*?\.([^\s\.\(\)]+)\(.*?$/, "$1")))
                }
            }
        },
        "onComplete": function () { }
    }
)
```

# 打印 il2cpp 中返回的 c# string
第三个四字节是长度, 第四个四字节开始存放 utf-16 字符串.

```javascript
function attach_DecryptString(){
    var func = Module.getBaseAddress("libil2cpp.so").add(0x3D270)
    console.log('func addr: ' + func)
    Interceptor.attach(func, {
        onEnter: function (args) {

        },
        onLeave: function (retval) {
            print_dotnet_string("onLeave", retval)
        }
    }
    )
}    

function print_dotnet_string(tag, dotnet_string) {
    console.log(JSON.stringify({
        tag: tag,
        len: dotnet_string.add(8).readU32(),
        data: dotnet_string.add(12).readUtf16String(-1)
    }))
}
```

# 读取 std::string
```javascript
/*
 * Note: Only compatible with libc++, though libstdc++'s std::string is a lot simpler.
 */

function readStdString (str) {
  const isTiny = (str.readU8() & 1) === 0;
  if (isTiny) {
    return str.add(1).readUtf8String();
  }

  return str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}
```

# 参考
```
https://codeshare.frida.re/
rOysue 的星球
https://api-caller.com/2019/03/30/frida-note/
```
