# ceserver

# Build

  - Linux:gcc
  - AndroidNDK(ndk-build)

The following explanation is for ceserver only.
#### Linux
・gcc

in directory of  
cheat-engine/CheatEngine/ceserver/gcc  

```
make
```

#### Android
・AndroidNDK(ndk-build)
Set the path to NDK with the system environment variable.  
```
EXECUTABLE
 └─jni
          Android.mk
          Application.mk
```

In the above state, move to the EXECUTABLE folder at the command prompt and execute `ndk-build`.

# Usage
### Linux
 - Start ceserver with administrator privileges.`sudo ./ceserver`
 - Start Cheat Engine via Wine, or if you are running Linux on a virtual machine, start Cheat Engine on the host OS.
 - Select the Network tab of the process list. In the Host field, enter localhost (via Wine) or Guest OS ip (on a virtual machine).

### Android
 - Execute `su` and start ceserver with root privileges.
 - Run the adb command on the PC.`adb forward tcp:52736 tcp:52736`
 - Start Cheat Engine.
 - Select the Network tab of the process list. In the Host field, enter localhost (Android Emulator) or Android device ip address (real Android device).
 
### Execution options
 - `-a`
Perform module enumeration only for the specified process ID.
 - `-m` 
If `1` is specified, memory is read and written only with the ptrace privilege, not via the virtual file system.
 - `-p`
Listen on the specified port number instead of the default 52736.

 - `-s`
It is disassembled with the specified architecture regardless of the ceserver architecture. It is convenient to specify with Android emulator (x86 and ARM are mixed)etc.  
i386=>0  
x86_64=>1  
arm=>2  
aarch64=>3  

 - `-t`
Start ceserver in test mode.

# Compression (LZ4)

`CMD_READPROCESSMEMORY` accepts a `compressed` byte in `CeReadProcessMemoryInput`:

| Value | Meaning |
|---|---|
| `0` | no compression |
| `1..9` | zlib level (legacy behavior) |
| `10` | LZ4 block |

The response framing is the same for both: `{ uncompressedSize, compressedSize }` followed by the payload.

On the client, open **Network -> Compression level** and check **LZ4 (fast)**. The checkbox sets the level to 10 and disables the zlib slider.

Building requires `liblz4-dev` (Linux) or the lz4 library available to the NDK build.

# TLS

TLS is optional and currently supported on Linux only. The Android build does not enable it because the NDK does not ship OpenSSL.

## Server

```
sudo ./ceserver -T -c server.pem -k server.key
```

Generate a self-signed certificate once:

```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.pem -days 365 \
  -subj "/CN=OnyxEngine" -addext "subjectAltName=IP:127.0.0.1"
```

At startup the server prints the certificate SHA-256 fingerprint and writes it to `ceserver-tls.fingerprint`.

## Client

1. In the process list, open the **Network** tab.
2. Check **Use TLS** before connecting.

The first successful handshake adopts the server fingerprint (TOFU) and stores it under:

```
HKCU\Software\OnyxEngine\TLS\<host>
```

Later connections must present the same fingerprint; otherwise the handshake is refused. Delete that registry value to re-trust a rotated certificate.

## Limitations

- TLS is not enabled in the Android/aarch64 builds yet.
- The aarch64 Linux build still requires the register-context/ptrace port (see the `context.h`/`api.c` platform branches); only x86_64 is validated by CI.