![ToothPicker Logo](assets/toothpicker.png)


# ToothPicker
ToothPicker is an in-process, coverage-guided fuzzer for iOS. It was developed to
specifically targets iOS's Bluetooth daemon ``bluetoothd`` and to analyze various
Bluetooth protocols on iOS. As it is built using [FRIDA](https://frida.re/), it can be
adapted to target any platform that runs FRIDA.

This repository also includes an over-the-air fuzzer with an exemplary implementation
to fuzz Apple's MagicPairing protocol using
[InternalBlue](https://github.com/seemoo-lab/internalblue). Additionally, it contains
the ``ReplayCrashFile.py`` script that can be used to verify crashes the in-process
fuzzer has found.

## New: Inplace Fuzzer (ToothFlipper)
This is a very simple fuzzer that only flips bits and bytes in active connections.
No coverage-guidance, no injection, but nice as a demo and stateful.
Runs just with Python+Frida, no modules or installation required.
Tested on iOS 13.5-14.3. See [inplace-fuzzer](inplace-fuzzer/).

## In-Process Fuzzer
The In-Process Fuzzer works out-of-the-box on various iOS versions (13.3-13.7 tested), but
 [symbols need to be specified](harness/symbols.js). Other iOS versions
require adaptions to function addresses. Additionally, it seems like FRIDA's stalker
has some problems with the iPhone 8. On newer iPhones that support
[PAC](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html),
the performance significantly suffers from signing pointers. Thus, it is recommended to
run this on an iPhone 7.

`ToothPicker` is built on the codebase of
[frizzer](https://github.com/demantz/frizzer). However, it has been adapted for this
specific application as therefore not compatible with the original version anymore.
There exist plans to replace this with a more dedicated component in the future.

### Prerequesits:
*On the iPhone*:
 - https://frida.re/docs/ios/
 
*On Linux*:
 - [usbmuxd](https://github.com/libimobiledevice/usbmuxd)
 - [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)
 - Optional but recommended: [virtualenv](https://virtualenv.pypa.io/en/latest/)
 - [radamsa](https://gitlab.com/akihe/radamsa) (needed by frizzer)

**For Arch-based Linux:**
```bash
# usbmuxd typically comes with libimobiledevice
# but just to be sure, we manually install it as well
sudo pacman -S usbmuxd libimobiledevice python-virtualenv radamsa

# Connect the iPhone to the computer
# Unlock it.
# If a pairing message pops up, click "Trust"
# If no pairing message pops up:
idevicepair pair
# Now there should be the pop up, accept and then again:
idevicepair pair

# In case of connection errors:
sudo systemctl restart usbmuxd
# or pair phone and computer again


# Other useful commands

# To ssh into the iPhone:
# Checkra1n comes with an SSH server listening on Port 44
# Proxy the phone's SSH port to 4444 localport:
iproxy 4444 44
# Connect:
ssh root@localhost -p 4444
# Default password: alpine

# To fetch some device information of the phone:
ideviceinfo
```

**For Debian Linux:**

Almost the same as above. Exceptions:

* `radamsa` needs to be installed from the [git repository](https://gitlab.com/akihe/radamsa) because
it is not packaged.
* The command `iproxy` requires the additional package `libusbmuxd-tools`.

**For macOS**:

Slightly different commands compared to the Arch Linux setup...
```bash
brew install libimobiledevice usbmuxd radamsa npm
idevicepair pair
npm install frida-compile
pip3 install frida-tools
```

On macOS, *PacketLogger*, which is part of the [Additional Tools for Xcode](https://developer.apple.com/bluetooth/),
can decode various packets once the [Bluetooth Debug Profile](https://developer.apple.com/bug-reporting/profiles-and-logs/?name=bluetooth)
is installed.
Moreover, if you open iOS crash logs with *Xcode*, it will add some symbols. 


### Setup and Fuzzing
**Setup:**
- It is recommended to set up a virtual Python environment for `frizzer`.
- Install the required packages by running in the `frizzer` directory.
- The `projects` directory contains an example project to fuzz the `MagicPairing` protocol. 
- To build the harness compile the general harness and the specialized `MagicPairing` harness into one file.
- `cd` into the `harness` directory and install [`frida-compile`](https://github.com/frida/frida-compile).
  Note that this needs to be run in that folder and can be directly installed as user by running `npm install frida-compile`.
- Now run `frida-compile ../projects/YOUR_PROJECT/YOUR_SPECIALIZED_HARNESS.JS -o ../projects/YOUR_PROJECT/harness.js`. 
  As this was installed in npm context it might require running `npx frida-compile` instead.
  Each time the harness changes, you need to rerun `frida-compile`.

**Fuzzing:**
- Connect an iOS device to your computer.
- It is advisable to put the phone in flight mode and turn on the "Do not disturb" feature to limit any other activity on the phone.
- Run `killall -9 bluetoothd` to freshly start `bluetoothd`.
- Make sure the phone does not connect to other Bluetooth devices.
- Now, `cd` back into your project's directory, create the crashlog-directory (`mkdir crashes`) and run `../../frizzer/fuzzer.py fuzz -p .`
- Yay! Now collect zero days and obtain large amounts of cash from Apple! (Or collect a huge list of useless NULL-pointer dereferences...)

  
In short, for starting a new project, run:
```bash
cd harness
npx frida-compile ../projects/YOUR_PROJECT/YOUR_SPECIALIZED_HARNESS.JS -o ../projects/YOUR_PROJECT/harness.js
cd ../projects/YOUR_PROJECT/
mkdir crashes
frizzer fuzz -p .
```

You can start with a different seed by using ``frizzer fuzz --seed 1234 -p .``.

**Adding new iOS versions:**

Currently, different versions of iOS are defined in `bluetoothd.js`. You can find these with the Ghidra
versioning tool given an initial version that has all the required symbols. Note that some of them are not
named in the original iOS binary, so ideally start with one that was already annotated before.
Each time the `bluetoothd.js` changes, you need to re-run `frida-compile`.


**Increasing bluetoothd capacities:**

iOS crash logs are stored in `Settings -> Privacy -> Analytics & Improvements -> Analytics Data`.
If they contain `bluetoothd` crashes of the pattern `bluetoothd.cpu_resource-*.ips` this indicates
that the crash was caused due to exceeding resources. They can be increased as follows.

On an iPhone 7, run:
```bash
cd /System/Library/LaunchDaemons/
plistutil -i com.apple.jetsamproperties.D10.plist -o com.apple.jetsamproperties.D10.plist.txt
plistutil -i com.apple.jetsamproperties.D101.plist -o com.apple.jetsamproperties.D101.plist.txt
```

On iPhone SE2, these are in `com.apple.jetsamproperties.D79.plist`.:
```bash
cd /System/Library/LaunchDaemons/
plistutil -i com.apple.jetsamproperties.D79.plist -o com.apple.jetsamproperties.D79.plist.txt
```

Search for `bluetoothd`, update the priority to 19 (highest valid priority) and set the memory limit to something very high.
Apply the same changes to both files.

```xml
<dict>
       <key>ActiveSoftMemoryLimit</key>
       <integer>24000</integer>
       <key>InactiveHardMemoryLimit</key>
       <integer>24000</integer>
       <key>EnablePressuredExit</key>
       <false/>
       <key>JetsamPriority</key>
       <integer>19</integer>
</dict>
```

Write the changes back and restart `bluetoothd`.
```bash
plistutil -i com.apple.jetsamproperties.D10.plist.txt -o com.apple.jetsamproperties.D10.plist
plistutil -i com.apple.jetsamproperties.D101.plist.txt -o com.apple.jetsamproperties.D101.plist
killall -9 bluetoothd
```

Respectively on the iPhone SE2:
```bash
plistutil -i com.apple.jetsamproperties.D79.plist.txt -o com.apple.jetsamproperties.D79.plist
killall -9 bluetoothd
```

**Deleting old logs:**

iOS stops saving crash logs for one program after the limit of 25 is reached. If loading a crash log
with Xcode (via Simulators&Devices), some symbols are added to the stack trace.
Once the limit is reached, the logs can either be removed via Xcode or directly on the iOS device
by deleting them in the folder `/var/mobile/Library/Logs/CrashReporter/`.

**A12+:**

Starting from the iPhone XR/Xs, PAC has been introduced. This requires calling `sign()` on `NativeFunction`
in FRIDA. While this is a no-op on earlier CPUs, this tremendously reduces speed on newer devices, but
is required to make them work at all. We observed that *ToothPicker* operates at half the speed when using
an iPhone SE2 instead of an iPhone 7.

## Over-the-Air Fuzzer and Crash Replay
The `MagicPairing` implementation of the over-the-air fuzzer requires InternalBlue to be installed and
can be executed by running `python MagicPairingFuzzer.py TARGET_BD_ADDR`. 

If you want to reproduce crashes, use the [ReplayCrashFile.py](ota-fuzzer/ReplayCrashFile.py) script, which
can take a crash file and initiates an over-the-air connection with a payload based on the
crash.
