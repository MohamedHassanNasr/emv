#ifndef MOCK_L1_H
#define MOCK_L1_H

#include "emv.h"
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>

using namespace emv;

class mock_module : public emv_module {
public:
    mock_module() : emv_module{}, express_mode(false){};

    virtual bool are_you(EMV_MODULE who) const override {
        return who == EMV_MODULE::TERMINAL || who == EMV_MODULE::L1;
    };

    void set_mock(const char* filename) {
        std::ifstream f(filename);
        std::string str((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
        json j = json::parse(str);

        not_found = j["not-found"];
        randoms = j["randoms"];
        yymmdd = j["date"];
        hhmmss = j["time"];

        transaction_req = j["transaction-req"];
        auto j_apdus = j["apdus"];
        for (auto& j_apdu : j_apdus) {
            std::string cmd = j_apdu["cmd"];
            std::string resp = j_apdu["resp"];
            apdus.insert(std::make_pair(cmd, resp));
        }
    };

    virtual void handle_message(const message& msg) override {
        auto id = msg.get_message_id();
        switch (id) {
        case MESSAGE_ID::TERMINAL_TRANSACTION_COMPLETE: {
            auto body = msg.get_body();
            logger.debug("<< ==== TERMINAL TRANSATION COMPLETE ===>>\n");
            if (body.size() > 0) {
                logger.debug("CVM : ", emv::to_string(narrow_cast<OUTCOME_CVM>(body[0])), "\n");
                secure_vector record{body.begin() + 1, body.end()};
                logger.debug("RECORD ", record, "\n");
            };
            break;
        }
        case MESSAGE_ID::TERMINAL_UI_REQ: {
            logger.debug("<< ====  TERMINAL MESSAGE ====>>\n");
            auto body = msg.get_body();
            logger.debug("MESSAGE: ", to_string(static_cast<ui_message_id>(body[0])), "\n");
            logger.debug("STATUS: ", to_string(static_cast<ui_status_id>(body[1])), "\n");
            // TODO later
#if 0
            auto qualifier = static_cast<ui_value_id>(body[2]);
            secure_vector value(body.begin() + 3, body.begin() + 9);
            secure_vector currency(body.begin() + 9, body.end());

            if (qualifier == ui_value_id::AMOUNT) {
                logger.debug("Amount : <currency code ", currency, "> ", value, "\n");
            } else if (qualifier == ui_value_id::BALANCE) {
                logger.debug("Blance : <currency code ", currency, "> ", value, "\n");
            };
#endif
            break;
        }
        case MESSAGE_ID::L1_POWER_UP: {
            secure_vector resp;
            if (express_mode) {
                for (auto& p : apdus) {
                    auto sel = p.first.substr(0, 8);
                    if (sel != "00A40400") { // SELECT?
                        continue;
                    };

                    if (p.first != std::string("00A404000E325041592E5359532E444446303100")) {
                        // not SELECT PPSE
                        logger.debug("express mode started : ", p.first, "\n");
                        resp = hex2vector(p.second);
                    }
                };
            };
            message out{MESSAGE_ID::L1_CARD_DETECTED, EMV_MODULE::L1, EMV_MODULE::L2, resp};
            out.send();
            break;
        }
        case MESSAGE_ID::L1_POWER_DOWN:
            break;
        case MESSAGE_ID::L1_RESET:
            break;
        case MESSAGE_ID::TERMINAL_ONLINE_REQ: {
            pr_debug("<< ======= TERMINAL ONLINE =====>\n");
            auto body = msg.get_body();
            logger.debug("CVM : ", emv::to_string(narrow_cast<OUTCOME_CVM>(body[0])), "\n");
            secure_vector record{body.begin() + 1, body.end()};
            logger.debug("RECORD ", record, "\n");

            secure_vector resp;
            message out{MESSAGE_ID::L2_CONTINUE_TRANSACT_WITH_ONLINE_RESP, EMV_MODULE::TERMINAL, EMV_MODULE::L2, resp};
            out.send();
            break;
        }
        case MESSAGE_ID::L1_TX_DATA: {
            secure_string body = vector2hex(msg.get_body());
            auto p = apdus.find(std::string(body.begin(), body.end()));
            secure_vector resp;
            if (p != apdus.end()) {
                resp = hex2vector(p->second);
            } else {
                resp = hex2vector(not_found);
            }

            message out{MESSAGE_ID::L1_DATA_RECEIVED, EMV_MODULE::L1, EMV_MODULE::L2, resp};
            out.send();
            break;
        }
        default:
            break;
        }
    };

    void start_transaction() {
        auto req = hex2vector(transaction_req);

        tlv_db transaction_req{};
        transaction_req.parse(req);

        // insert missing element into request
        secure_vector randoms(UNPREDICTABLE_NUMBER_9F37.maxlen);
        get_randoms(randoms.data(), randoms.size());
        transaction_req.emplace(UNPREDICTABLE_NUMBER_9F37.id, randoms);
        transaction_req.emplace(TRANSACTION_DATE_9A.id, get_yymmdd());
        transaction_req.emplace(TRANSACTION_TIME_9F21.id, get_hhmmss());
        message out{MESSAGE_ID::L2_START_TRANSACTION, EMV_MODULE::TERMINAL, EMV_MODULE::L2, transaction_req.serialize()};
        out.send();
    };

    void get_randoms(uint8_t* ptr, size_t length) {
        if (randoms.size() == 0)
            randoms = "ABABABAB";
        logger.debug("....... feeding mock randoms ", randoms, " .........\n");
        auto tmp = hex2vector(randoms);
        for (auto p : tmp) {
            if (length-- > 0) {
                *ptr++ = p;
            }
        }
    };

    secure_vector get_yymmdd() {
        return hex2vector(yymmdd);
    };

    secure_vector get_hhmmss() {
        return hex2vector(hhmmss);
    };

    void set_express_mode(bool express) {
        express_mode = express;
    };

private:
    bool express_mode;
    std::string not_found;
    std::map<std::string, std::string> apdus;
    std::string randoms;
    std::string yymmdd;
    std::string hhmmss;
    std::string transaction_req;
};

#endif
