#!/bin/bash --posix
nfdc strategy set / /localhost/nfd/strategy/multicast
i=0
while [ $i -ne 1 ]
do
    i=$(($i+1))
    export NODE_ID=$i
    deno task get_info &
    sleep 1
done