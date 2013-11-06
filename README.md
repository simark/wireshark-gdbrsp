wireshark-gdbrsp
================

My attempt at a Wireshark dissector for GDB's remote serial protocol.

    mkdir build
    cd build
    cmake ..
    make
    make install

This will build the .so plugin for wireshark and install it into the user's ~/.wireshark/plugins/ directory, where wireshark will load plugins from.

Currently, the dissector looks for communication on TCP port 1234. Since there is no well-known port for RSP, the correct solution would probably involve [heuristic dissectors](http://anonsvn.wireshark.org/wireshark/trunk/doc/README.heuristic). In the mean time, you can always right click on a packet you know is part of an RSP communication and choose "Decode As..." and then "GDB RSP".
