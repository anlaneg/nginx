#! /bin/bash
if [ ! -f Makefile ]; then
./auto/configure
fi;
make
