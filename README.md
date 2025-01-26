# uwstest
Small webserver for experimenting with [µWebSockets](https://github.com/uNetworking/uWebSockets)
together with external libuv event loop.

## Download
Clone the `uwstest` repository with submodules:

```console
git clone --recurse-submodules https://github.com/johanhedin/uwstest.git
```

## Install dependencies
`uwstest` requires a C++20 compiler, `cmake` version 3 and depend on the `zlib`,
`libuv`, `openssl`, `fmt` and `spdlog` libraries. Compiler and libraries can be
installed with:

```console
sudo dnf install gcc-c++ cmake zlib-devel libuv-devel openssl-devel fmt-devel spdlog-devel
```

on Fedora/Rocky Linux 9/RHEL 9 and with:

```console
sudo apt-get install g++ cmake zlib1g-dev libuv1-dev libssl-dev libfmt-dev libspdlog-dev
```

on Debian(Bookworm)/Ubuntu(LTS 22.04 and LTS 24.04)/Raspberry Pi OS(Bookworm).

On Rocky/RHEL, the `epel` and `crb` repositories need to be activated as well.


## Build
Build everything including the bundled uSockets with:

```console
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```


## Run
Run `uwstest` from the build directory with:

```console
./uwstest
```

Stop with `Ctrl-C`.

The server will by default bind to `127.0.0.1` on port 8080. If a TLS
key/certificate file pair exist in the directory above the build directory,
the TLS server will bind to to `0.0.0.0` on port 8443 as well.

The keyfile should be named `../srv.key` and the certificate file `../srv.crt`.
