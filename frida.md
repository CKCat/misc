
# frida版 通过dexfile指针 获得 类列表
```js
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
