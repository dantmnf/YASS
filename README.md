## YASS - Yet Another Shadowsocks ##
This program implements the Shadowsocks protocol in C#

#### To-do list ####
* [x] TCP relay server
* [x] HMAC support for TCP relay server (known as One Time Auth in other ports)
* [ ] TCP relay client
* [ ] Everything about UDP

### Building ###
The `Any CPU` architecture neither copies OpenSSL libraries to output path, nor prefers 32-bit runtime.
You should provide proper OpenSSL library.

#### Mono Compatibility ####
Not guranteed. Currently the MSIL binaries can run in Mono with DLL maps.
