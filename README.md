# uwstest
Small webserver for experimenting with [µWebSockets](https://github.com/uNetworking/uWebSockets)
together with external libuv event loop.

## Download
Clone the `uwstest` repository with submodules:

```console
git clone --recurse-submodules https://github.com/johanhedin/uwstest.git
```

## Build
Build everything (including the bundled uSockets) with:

```console
cd uwstest
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

`uwstest` requires `zlib`, `libuv` and `openssl` so make sure they are installed
togehter with their respective development packages.


## Run
Run `uwstest` from the build directory with:

```console
./uwstest
```

Stop with `Ctrl-C`.
