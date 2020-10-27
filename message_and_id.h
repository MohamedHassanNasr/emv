/* message_and_id.h - EVM inter-process communication definition
 * Copyright 2019 Daniel Hu <daddy.of.qq@gmail.com>
 *
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

#ifndef MESSAGE_AND_ID_H
#define MESSAGE_AND_ID_H

#include <cstdint>

namespace emv {
enum class ui_message_id : uint8_t {
    APPROVED = 0x03,
    NOT_AUTHORIZED = 0x07,
    ENTER_PIN = 0x09,
    PROCESSING_ERR = 0xF,
    REMOVE_CARD = 0x10,
    WELCOME = 0x14,
    PRESENT_CARD = 0x15,
    PROCESSING = 0x16,
    READ_OK = 0x17,
    INSERT_OR_SWIPE = 0x18,
    PRESENT_ONE_ONLY = 0x19,
    APPROVED_PLEASE_SIGN = 0x1A,
    AUTHORISING = 0x1B,
    INSERT_SWIPE_TRY_ANOTHER = 0x1C,
    INSERT_CARD = 0x1D,
    NO_MESSAGE = 0x1E,
    CHECK_PHONE = 0x20,
    TRY_AGAIN = 0x21,
    NA = 0xFF
};

enum class ui_status_id : uint8_t {
    NOT_READY = 0x00,
    IDLE = 0x01,
    PRESENT_CARD = 0x02,
    PROCESSING = 0x03,
    CARD_READ_OK = 0x04,
    PROCESSING_ERR = 0x05,
    CONTACTLESS_NOT_SATISFIED = 0x06,
    COLLISION_ERR = 0x07,
    CARD_NOT_REMOVED = 0x08,
    NA = 0xFF,
};

enum class ui_value_id : uint8_t {
    NONE = 0,
    AMOUNT = 0x01,
    BALANCE = 0x02,
    NA = 0,
};

enum class EMV_MODULE : uint8_t {
    TERMINAL = 0,
    L1,
    L2,
    ROUTER
};

enum class MESSAGE_ID : uint8_t {
    L1_POWER_UP,
    L1_POWER_DOWN,
    L1_RESET,
    L1_TX_DATA,
    L1_DATA_RECEIVED,
    L1RSP,
    L2_START_TRANSACTION,
    ROUTER_INIT,
    L1_CARD_DETECTED,
    L1_COLLISION_DETECTED,
    TERMINAL_UI_REQ,
    TERMINAL_PIN_CAPTURE,
    TERMINAL_ONLINE_REQ,
    TERMINAL_TRANSACTION_COMPLETE,
    L2_CONTINUE_TRANSACT_WITH_ONLINE_RESP,
    DEK,
    DET,
};

enum class OUTCOME_CVM : uint8_t {
    NO_CVM = 0,
    SIGNATURE = 1,
    ONLINE_PIN = 2,
    CONF_CODE_VERIFIED = 3,
    NA = 0x0F
};

}; // namespace emv

#endif

