var kernel32 = Process.getModuleByName("kernel32.dll");
var GetProcAddress_ptr = kernel32.getExportByName("GetProcAddress");
var GetTickCount_ptr = kernel32.getExportByName("GetTickCount");
var GetTickCount64_ptr = kernel32.getExportByName("GetTickCount64");
var sleep_ptr = kernel32.getExportByName("Sleep");
var sleepex_ptr = kernel32.getExportByName("SleepEx");

const sections = [
  { name: ".text", start: 0x401000, end: 0x4c7000, track: true },
  { name: ".idata", start: 0x4c7000, end: 0x4c73d8, track: true },
  { name: ".tss_8a", start: 0x4c73d8, end: 0x4c9000, track: true },
  { name: ".tss_8b", start: 0x4c9000, end: 0x4cc000, track: true },
  { name: ".tss_8c", start: 0x59d000, end: 0x688000, track: true },
];

function print_module_info(hModule) {
  var moduleInfo = Process.findModuleByAddress(hModule);
  if (moduleInfo) {
    console.log("Module handle info:");
    console.log("  Name:", moduleInfo.name);
    console.log("  Base:", moduleInfo.base);
    console.log("  Size:", moduleInfo.size);
    console.log("  Path:", moduleInfo.path);
  } else {
    console.log("Module not found for address: " + hModule);
  }
}

function should_process(return_address, function_name, print_call) {
  for (let section of sections) {
    if (
      return_address > section.start &&
      return_address < section.end &&
      section.track
    ) {
      if (print_call) {
        console.log(
          `\n-----------------------------------------------------------`,
        );
        console.log(`${function_name} called from section:`, section.name);
      }
      return true;
    }
  }
  var module = Process.findModuleByAddress(return_address);
  if (module) {
    return false;
  } else {
    if (print_call) {
      console.log(
        `\n-----------------------------------------------------------`,
      );
      console.log(
        `${function_name} called from non image backed location`,
        return_address,
      );
    }
    return true;
  }
}

var hookedFunctions = {};

Interceptor.attach(GetProcAddress_ptr, {
  onEnter: function (args) {
    if (should_process(this.returnAddress, "GetProcAddress", true)) {
      console.log("the return address is: " + this.returnAddress);
      console.log("running on thread: " + this.threadId);

      print_module_info(args[0]);

      this.buffer = args[1];
      this.funcName = this.buffer.readCString();
      console.log("requested export: " + this.funcName);
    }
  },
  onLeave: function (retval) {
    if (should_process(this.returnAddress, "GetProcAddress", true)) {
      console.log("return address:", retval);
      if (!retval.isNull() && this.funcName) {
        var hookKey = retval.toString();
        if (
          !hookedFunctions[hookKey] &&
          !this.funcName.toLowerCase().includes("gettickcount") &&
          !this.funcName.toLowerCase().includes("sleep")
        ) {
          hookedFunctions[hookKey] = this.funcName;

          try {
            Interceptor.attach(retval, {
              onEnter: function (args) {
                if (
                  should_process(
                    this.returnAddress,
                    hookedFunctions[hookKey],
                    true,
                  )
                ) {
                  console.log("the return address is: " + this.returnAddress);
                  console.log("running on thread: " + this.threadId);
                }
                this.funcName = hookedFunctions[hookKey];
              },
            });

            console.log("hooked: " + this.funcName);
          } catch (e) {
            console.log("failed to hook " + this.funcName + ": " + e.message);
          }
        }
      }
    }
  },
});

Interceptor.attach(GetTickCount_ptr, {
  onEnter: function (args) {
    if (should_process(this.returnAddress, "GetTickCount", true)) {
      console.log("the return address is: " + this.returnAddress);
      console.log("running on thread: " + this.threadId);
    }
  },

  onLeave: function (retval) {
    retval.replace(0xdead);
  },
});

Interceptor.attach(GetTickCount64_ptr, {
  onEnter: function (args) {
    if (should_process(this.returnAddress, "GetTickCount64", true)) {
      console.log("the return address is: " + this.returnAddress);
      console.log("running on thread: " + this.threadId);
    }
  },

  onLeave: function (retval) {
    retval.replace(0xdead);
  },
});

Interceptor.attach(sleep_ptr, {
  onEnter: function (args) {
    if (should_process(this.returnAddress, "Sleep", false)) {
      args[0] = ptr(0);
    }
  },
});

Interceptor.attach(sleepex_ptr, {
  onEnter: function (args) {
    if (should_process(this.returnAddress, "SleepEx", false)) {
      args[0] = ptr(0);
    }
  },
});
