#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "emv.h"
#include <exception>
#include <nlohmann/json.hpp>
#include <string>

using json = nlohmann::json;

using namespace emv;
using namespace emv::contactless;

class emvCfgParser {
public:
    static bool parse(const std::string& cfg_json, std::vector<reader_cfg>& dependencies, reader_cfg& cfg, reader_cfg* predecessor = nullptr) {
        json j = json::parse(cfg_json);

        auto j_parent = j["parent"];
        if (!j_parent.is_null() && j_parent.is_string()) {
            auto name = std::string(j_parent);
            bool found = false;
            for (auto& d : dependencies) {
                if (d.name == name) {
                    found = true;
                    cfg = d;
                }
            };
            if (!found) {
                pr_warn("dependency ", name, " not found, igore!!!\n");
                return false;
            };
        } else if (predecessor != nullptr) {
            cfg = *predecessor;
        };

        auto j_name = j["name"];
        if (!j_name.is_null()) {
            cfg.name = j_name;
        } else {
            cfg.name = std::string{};
        };

        auto j_terminal = j["terminal"];
        parse_tlv(cfg.terminal_cfg, j_terminal);

        auto j_pks = j["publicKey"];
        if (!j_pks.is_null()) {
            parse_pks(cfg.pks, j_pks);
        };

        auto j_exceptons = j["exceptionFile"];
        for (auto& j_exception : j_exceptons) {
            if (!j_exception.is_null() && j_exception.is_string()) {
                cfg.exceptions.insert(std::string(j_exception));
            };
        }

        auto j_kernels = j["kernel"];
        for (auto& j_k : j_kernels) {
            auto kid = narrow_cast<KERNEL_ID>((int)j_k["kernelId"]);
            auto kpos = std::find_if(cfg.kernel_cfgs.begin(), cfg.kernel_cfgs.end(), [&](auto& c) { return c.kid == kid; });
            if (kpos == cfg.kernel_cfgs.end()) {
                kernel_cfg tmp{};
                tmp.kid = kid;
                cfg.kernel_cfgs.push_back(tmp);
                kpos = std::find_if(cfg.kernel_cfgs.begin(), cfg.kernel_cfgs.end(), [&](auto& c) { return c.kid == kid; });
            }

            kernel_cfg& kcfg = *kpos;
            auto cap = j_k["terminalEntryCapability"];
            if (!cap.is_null() && cap.is_number()) {
                kcfg.terminalEntryCapability = (int)cap;
            };

            auto b = j_k["fddaForOnlineSupported"];
            if (!b.is_null() && b.is_boolean()) {
                kcfg.fddaForOnlineSupported = b;
            }

            b = j_k["displayAvailableSpendingAmount"];
            if (!b.is_null() && b.is_boolean()) {
                kcfg.displayAvailableSpendingAmount = b;
            }

            b = j_k["aucManualCheckSupported"];
            if (!b.is_null() && b.is_boolean()) {
                kcfg.aucManualCheckSupported = b;
            }

            b = j_k["aucCashbackCheckSupported"];
            if (!b.is_null() && b.is_boolean()) {
                kcfg.aucCashbackCheckSupported = b;
            }

            b = j_k["atmOfflineCheck"];
            if (!b.is_null() && b.is_boolean()) {
                kcfg.atmOfflineCheck = b;
            }

            b = j_k["exceptionFileEnabled"];
            if (!b.is_null() && b.is_boolean()) {
                kcfg.exceptionFileEnabled = b;
            }

            auto j_k_cfg = j_k["config"];
            parse_tlv(kcfg.db, j_k_cfg);
            auto j_applications = j_k["application"];
            for (auto& j_app : j_applications) {
                auto aid = hex2vector(j_app["aid"]);

                auto apos = std::find_if(kcfg.app_cfgs.begin(), kcfg.app_cfgs.end(), [&](auto& c) { return c.aid == aid; });
                if (apos == kcfg.app_cfgs.end()) {
                    application_cfg tmp{};
                    tmp.aid = aid;
                    kcfg.app_cfgs.push_back(tmp);
                    apos = std::find_if(kcfg.app_cfgs.begin(), kcfg.app_cfgs.end(), [&](auto& c) { return c.aid == aid; });
                }

                application_cfg& acfg = *apos;
                auto j_app_cfg = j_app["config"];
                parse_tlv(acfg.db, j_app_cfg);
                auto j_app_transactions = j_app["transaction"];
                for (auto& j_tr : j_app_transactions) {
                    TRANSACTION_TYPE transact_type = narrow_cast<TRANSACTION_TYPE>((int)j_tr["transactionType"]);
                    auto tpos = std::find_if(acfg.tr_cfgs.begin(), acfg.tr_cfgs.end(), [&](auto& c) { return c.transact_type == transact_type; });
                    if (tpos == acfg.tr_cfgs.end()) {
                        transaction_cfg tmp{};
                        tmp.transact_type = transact_type;
                        acfg.tr_cfgs.push_back(tmp);
                        tpos = std::find_if(acfg.tr_cfgs.begin(), acfg.tr_cfgs.end(), [&](auto& c) { return c.transact_type == transact_type; });
                    };
                    transaction_cfg& tcfg = *tpos;
                    auto j_tr_cfg = j_tr["config"];
                    parse_tlv(tcfg.db, j_tr_cfg);
                    parse_tr_cfg(tcfg, j_tr);
                }
            }

            auto j_override = j_k["override"];
            if (!j_override.is_null()) {
                // overide for every transaction we have
                for (auto& acfg : kcfg.app_cfgs) {
                    for (auto& tcfg : acfg.tr_cfgs) {
                        parse_tlv(tcfg.db, j_override);
                    }
                }
            };
        }

        return true;
    };

private:
    template <typename TAGS>
    static void parse_tlv(tlv_db& db, TAGS& tlv_list) {
        for (auto tlv : tlv_list) {
            auto tag = hex2vector(tlv["tag"]);
            auto value = hex2vector(tlv["value"]);
            tlv_obj obj{vector2int(tag), std::move(value)};
            db.update(obj);
        }
    }

    template <typename CFGS>
    static void parse_pks(std::vector<cakey>& pks, CFGS& configs) {
        for (auto& p : configs) {
            struct cakey pk {};
            auto j_indicator = p["hashAlgorithmIndicator"];
            if (!j_indicator.is_null()) {
                pk.hashAlgorithmIndicator = (int)j_indicator;
            }

            j_indicator = p["publicKeyAlgorithmIndicator"];
            if (!j_indicator.is_null()) {
                pk.publicKeyAlgorithmIndicator = (int)j_indicator;
            }

            auto j_modulus = p["modulus"];
            if (!j_modulus.is_null()) {
                pk.modulus = hex2vector(j_modulus);
            }

            auto j_exponent = p["exponent"];
            if (!j_exponent.is_null()) {
                pk.exponent = hex2vector(j_exponent);
            }

            auto j_date = p["expiryDate"];
            if (!j_date.is_null()) {
                pk.expiryDate = j_date;
            };

            auto j_index = p["index"];
            if (!j_index.is_null()) {
                auto v = hex2vector(j_index);
                pk.index = v[0];
            };

            auto j_checksum = p["checksum"];
            if (!j_checksum.is_null()) {
                pk.checksum = hex2vector(j_checksum);
            }

            auto j_rid = p["rId"];
            if (!j_rid.is_null()) {
                pk.rid = hex2vector(j_rid);
            }

            bool override_ca = false;
            for (auto& p : pks) {
                if (p.index == pk.index && p.rid == pk.rid) {
                    pr_debug("override index ", emv::to_hex((uint32_t)p.index), " rid ", p.rid, "\n");
                    p = pk;
                    override_ca = true;
                    break;
                };
            };
            if (!override_ca)
                pks.push_back(pk);
        }
    };

    template <typename TR>
    static void parse_tr_cfg(transaction_cfg& cfg, TR& tr) {
        auto j_aid = tr["aid"];
        if (j_aid.is_null()) {
            logger.error("missing aid in transaction config\n");
            throw std::bad_exception();
        }
        cfg.aid = hex2vector(j_aid);

        auto flag = tr["statusCheckSupportFlag"];
        if (!flag.is_null() && flag.is_boolean()) {
            cfg.status_check_support = flag;
        }
        flag = tr["zeroAmountAllowedFlag"];
        if (!flag.is_null() && flag.is_boolean()) {
            cfg.zero_amount_allowed = flag;
        }
        flag = tr["extendedSelectionSupportFlag"];
        if (!flag.is_null() && flag.is_boolean()) {
            cfg.extended_selection_support = flag;
        }
        auto limit = tr["readerContactlessTransactionLimit"];
        if (!limit.is_null() && limit.is_number()) {
            cfg.reader_contactless_transaction_limit = limit;
        }

        limit = tr["readerContactlessFloorLimit"];
        if (!limit.is_null() && limit.is_number()) {
            cfg.reader_contactless_floor_limit = limit;
        }

        limit = tr["readerCVMRequiredLimit"];
        if (!limit.is_null() && limit.is_number()) {
            cfg.reader_cvm_required_limit = limit;
        }

        limit = tr["terminalFloorLimit"];
        if (!limit.is_null() && limit.is_number()) {
            cfg.terminal_floor_limit_9F1B = limit;
        }
    }
};

#endif
