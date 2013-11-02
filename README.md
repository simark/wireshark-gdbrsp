wireshark-gdbrsp
================

My attempt at a Wireshark dissector for GDB's remote serial protocol.

    mkdir build
    cd build
    cmake ..
    make
    make install

This will build the .so plugin for wireshark and install it into the user's ~/.wireshark/plugins/ directory, where wireshark will load plugins from.
