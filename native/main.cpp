/* main.cpp - 
 * Copyright 2019 Daniel Hu <daddy.of.qq@gmail.com>
 *
 * This file is mainly for EMV testing purpose on a Linux PC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 */

#include <iostream>
#include <vector>

#include "config_parser.h"
#include "emv.h"
#include "mock.h"
#include "os_linux.h"
#include <fstream>

using namespace std::chrono;

extern "C" void mbedtls_platform_zeroize(void* buf, size_t len) {
    memset(buf, 0, len);
}

#include "sha1.h"
void emv::compute_sha1(const uint8_t* data, size_t length, uint8_t* hash) {
    mbedtls_sha1_ret(data, length, hash);
}

#include "bignum.h"
void emv::bignum_exp_modulus(const secure_vector& base,
                             const secure_vector& exponent,
                             const secure_vector& modulus,
                             secure_vector& result) {
    mbedtls_mpi A, E, N, X;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X);

    mbedtls_mpi_read_binary(&A, base.data(), base.size());
    mbedtls_mpi_read_binary(&E, exponent.data(), exponent.size());
    mbedtls_mpi_read_binary(&N, modulus.data(), modulus.size());

    mbedtls_mpi_exp_mod(&X, &A, &E, &N, NULL);
    mbedtls_mpi_write_binary(&X, result.data(), result.size());
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&N);
}

void emv::Logger::log(const std::string& msg) {
    std::cout << msg;
};

void emv::Logger::log(const char* str) {
    std::cout << std::string(str);
};

emv::Logger emv::logger{};
global_locker Qlocker;

using namespace std;
using namespace emv;
using namespace emv::contactless;

unix_timer_factory local_timer_factory;
emv::timer_factory* emv::emv_timer_factory = &local_timer_factory;

static mock_module mock{};

bool mock_mode = false;
emv::contactless::reader_cfg contactless_cfg;
emv::contactless::modulel2 contactlessl2(contactless_cfg);
emv::mqueue queue(&Qlocker);

class udp_message_router router {
    &queue
};
message_router *emv::emv_message_router = &router;

#include "contactless_k3.h"
kernel3 k3{&contactlessl2};

#include "contactless_k2.h"
kernel2 k2{&contactlessl2};

class my_kernel_factory : public kernel_factory {
public:
    kernel* get_kernel(KERNEL_ID kid) override {
        if (kid == KERNEL_ID::KERNEL_3) {
            return &k3;
        } else if (kid == KERNEL_ID::KERNEL_2) {
            return &k2;
        };
        return nullptr;
    };
};
my_kernel_factory local_kernel_factory;
kernel_factory* emv::contactless::emv_kernel_factory = &local_kernel_factory;

static bool parse(const std::vector<std::string>& filenames, reader_cfg& cfg, const std::string& selection) {
    std::vector<reader_cfg> cfgs{};
    reader_cfg* last = nullptr;

    for (auto& file : filenames) {
        std::ifstream f(file);
        std::string str((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
        reader_cfg tmp{};
        bool ret = emvCfgParser::parse(str, cfgs, tmp, last);
        if (!ret) {
            pr_error("fail to parse config ", file, "\n");
            return false;
        }

        if (selection == tmp.name) {
            cfg = tmp;
            cfg.print();
            return true;
        }

        cfgs.push_back(tmp);
        last = &cfgs[cfgs.size() - 1];
    };

    if (selection.size() == 0 && cfgs.size() != 0) {
        cfg = cfgs[cfgs.size() - 1];
        cfg.print();
        return true;
    }

    pr_debug("do not find target config ", selection, "\n");
    return false;
};

int main(int argc, char* argv[]) {
    int index = 1;
    std::vector<std::string> cfgs{};
    std::string default_config{};
    queue.add_consumer(&contactlessl2);

    while (index < argc) {
        if (!strcmp(argv[index], "--ip")) {
            if (index + 1 < argc) {
                printf("connect to %s:9000\n", argv[index + 1]);
                router.set_address(9000, argv[++index], 9000);
            } else {
                printf("--ip [xx.xx.xx.xx]\n");
                exit(1);
            }
        } else if (!strcmp(argv[index], "--mock")) {
            if (index + 1 < argc) {
                queue.add_consumer(&mock);
                mock.set_mock(argv[++index]);
                mock_mode = true;
            } else {
                printf("--mock [mock file]\n");
                exit(1);
            }
        } else if (!strcmp(argv[index], "--set")) {
            if (index + 1 < argc) {
                default_config = std::string(argv[++index]);
            } else {
                printf("--set [config name]\n");
                exit(1);
            }
        } else if (!strcmp(argv[index], "--express")) {
            mock.set_express_mode(true);
        } else if (!strcmp(argv[index], "--cfg")) {
            while (index + 1 < argc) {
                cfgs.push_back(std::string(argv[++index]));
            }
        }

        index++;
    }

    if (cfgs.size() == 0) {
        cfgs.push_back(std::string("./default_emv_config.json"));
    };

    if (!parse(cfgs, contactless_cfg, default_config)) {
        exit(1);
    };

    std::thread t([&]() { router.start(); });

    if (mock_mode) {
        mock.start_transaction();
    }

    queue.loop();

    return 0;
}
