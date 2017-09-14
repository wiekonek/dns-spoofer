#include <iostream>
#include "ArpSpoofer.h"


int main() {
    auto arpSpoofer = new ArpSpoofer();
    arpSpoofer->start_spoofing("wlo1", "", "");


    return 0;
}