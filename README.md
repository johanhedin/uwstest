# uwstest
Small CMake based project for experimenting with embedding [µWebSockets](https://github.com/uNetworking/uWebSockets)
in a C++ application with external libuv event loop.

## Build
Clone `uwstest` with submodules to get µWebSockets:

```console
git clone --recurse-submodules https://github.com/johanhedin/uwstest.git
```

and then build with:

```console
cd uwstest
mkdir build
cd build
cmake ..
make
```

Make sure that development packages for `zlib`, `libuv` and `openssl` are installed.
