# Introduction

THIS PROJECT IS WORK IN PROGRESS.

Claim: This project use open source json implementation from git@github.com:nlohmann/json.git (which is a head-file based implementation convienient to use)
(make sure you did 'git submodule update --init --recursive' after cloning emv repo)

Contactless EMV is implemented using modern C++, you need c++17 compiler. So far we can do online/offline transaction for Visa/Mastercard

Some optional features are not fully implemented, like RRP, Magstripe, IDS, nor is the code certified.

the contactless EMV is designed for easy integration with a solution:

1) implementations all in header files, which can be directly included into target. Major header files include emv.h (emv common definitions), contactless_k2.h (Contactless Kernel 2) and contactless_k3.h (Contactless Kernel 3)

2) EMV modules or layers (L1, L2, L3) functions are separated using a generic message queue based communications, which can be mapped to any mechansim on a native system. For example, it's possible to run L1/L2 in two separate processes, or have them to talk to each other across network. all you need to do is to write a custom message router.

# Demo and Test
the code is designed to work a mock, or a true NFC reader (L1)

for example, following command can execute a mastercard offline transaction test based mock data (in this case, L1, L3 handling is based a mock handler)

./build/emv --mock ./mock/mock-msc-offline.json --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_PPS_MChip1.json ./cfg/cfg_PPS_Perf_MC.json

the test environment also allow you run you emv kernel from your PC, but run L1 NFC and terminal function from your Android phone. In this case there is an android app that talks to EMV kernel through UDP (message is routed across network between L1/L2)

emv --ip 192.168.178.35 --cfg ./cfg/cfg_default_terminal.json ./cfg/cfg_PPS_MChip1.json ./cfg/cfg_PPS_Perf_MC.json ./cfg/cfg_visa.json ./cfg/cfg_test_cert_override.json

Here 192.168.178.35 is the ip address of your phone.

some explanation for the  command "--cfg":

following the --cfg options are the emv config file. You are allowed to give multiple config. Each config has a specific name defined in file. It can also define a parent, in which case child inherit all config defined by parent (plus its own definition on top of it). If the config has no parent defined in file, it implicitly choose the config preceding in command line as parent (if it is not the first config, of course). 
the actual config to be used for running emv can be selected by "--set [config name]". If it's not explictly selected, the last config in command-line is chosen.

in above commandline, cfg_test_cert_override.json used some test CA key for test cards (if you are not using ca production key for smartcard).

This flexibility allow the solution to apply any configs at run time (it can be essential for certification process)

# HOW TO INTEGRATE
It's worth looking at main.cpp and os_linux.h (two files provided for test/demo on a Linux PC), which gives you the idea how to integrate the EMV stack with target solutions.

os_linux.h contains a implementation for udp messag router, which is a good reference for IPC between L1, L2, Terminal.

main.cpp implements the interface required by EMV kernel, like crypto, timing, config parsing, queue, main loop.

mock.h can be useful reference to implement the terminal function, where transaction is started, ui mesage displayed, and online request getting handled, as well as L1 messaging.

android nfc app (git@github.com:daddyofqq/nfc-reader.git) provides good reference in terms of how to integrate emv kernel into a real product. The android app has two modes. It can invoke emv kernel running in jni native, and also talk to a remote emv kernel through network.

The crypto for RSA, SHA1 (and AES to add later) are currently using mbedtls library. You are welcome to choose whatever is available on your target platform.
