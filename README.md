# uwstest
Small project for experimenting with embedding [uWebSockets](https://github.com/uNetworking/uWebSockets)
in a C++ application by using git submodules and CMake.

## Build
Build by checking out the repository and run cmake:

```console
git clone --resurse-submodules https://github.com/johanhedin/uwstest.git
cd uwstest
mkdir build
cd build
cmake ..
make
```
