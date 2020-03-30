/* contactless_k2.h - EVM Contactless Kernel 2 (Mastercard) Implementation
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

#ifndef CONTACTLESS_K2_H
#define CONTACTLESS_K2_H

// implementation of emv contactless Kernel 2

#include "emv.h"

namespace emv::contactless {
class kernel2 : public kernel {
    class database : public tlv_db {
    public:
        database() : tlv_db{} {};

        tlv_obj get_and_remove_from_list(std::vector<uint8_t>& list_data) {
            uint32_t tag = 0;
            uint8_t tagSize = 0;
            uint32_t length;
            auto begin = list_data.cbegin();
            auto end = list_data.cend();

            while (begin < end) {
                if (*begin == 0x00) {
                    begin++;
                    continue;
                }

                if (!tlv_get_tag(begin, end, tag, tagSize) ||
                    !tlv_get_length(begin, end, length) ||
                    begin + length > end) {
                    pr_error("got wrong list\n");
                    throw std::bad_exception();
                }

                std::vector<uint8_t> v{begin, begin + length};
                tlv_obj obj{tag, std::move(v)};
                list_data = std::vector<uint8_t>{begin + length, end};
                return obj;
            }

            return tlv_obj{};
        };

        bool update_with_det_data(std::vector<uint8_t> const& det_data) {
            pr_debug("update with DET:\n");
            auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                if (tag == TAGS_TO_READ_DF8112.id) {
                    tag_list_deserialize(begin, end, tags_to_read_yet);
                } else if (tag == TAGS_TO_WRITE_BEFORE_GEN_AC_FF8102.id) {
                    tags_to_write_yet_before_gen_ac.append(begin, end);
                } else if (tag == TAGS_TO_WRITE_AFTER_GEN_AC_FF8103.id) {
                    tags_to_write_yet_after_gen_ac.append(begin, end);
                } else if (!constructed) {
                    // IF
                    // [(IsKnown(T) OR IsPresent(T)) AND
                    // update conditions of T include DET Signal]
                    // THEN
                    // Store LV in the TLV Database for tag T
                    // ENDIF
                    // FIXME check update conditions
                    std::vector<uint8_t> v(begin, end);
                    tlv_print(tag, v);
                    tlv_obj tlv(tag, std::move(v));
                    insert(std::move(tlv));
                }
                return true;
            };
            return tlv_visit(det_data.begin(), det_data.end(), parser, false);
        };

        bool parse_store_card_response(std::vector<uint8_t> const& apdu) {
            auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                return save_tlv_from_card(tag, begin, end, constructed);
            };

            return tlv_visit(apdu.begin(), apdu.end() - 2, parser);
        };

        bool save_tlv_from_card(uint32_t tag, std::vector<uint8_t>::const_iterator begin,
                                std::vector<uint8_t>::const_iterator end, bool constructed) {
            if (!constructed) {
                if (has_tag(tag)) {
                    logger.error("duplicated tlv found from card ", to_hex(tag));
                    return false;
                };

                std::vector<uint8_t> v{begin, end};
                if (tag == TRACK2_57.id && has_tag(PAN_5A)) {
                    auto pan_5A = (*this)(PAN_5A);
                    auto pan_57 = TRACK2_57.get_pan(v);
                    if (pan_57 != pan_5A) {
                        pr_debug("pan error: 57 does not match existing 5A\n");
                        return false;
                    }
                } else if (tag == PAN_5A.id && has_tag(TRACK2_57)) {
                    auto& _v = (*this)[TRACK2_57];
                    if (TRACK2_57.get_pan(_v) != PAN_5A.to_string(v)) {
                        pr_debug("pan error : 5A does not match existing 57\n");
                        return false;
                    }
                }

                if (!tlv_validate(tag, v)) {
                    logger.error("tag ", to_hex(tag), " format error\n");
                    return false;
                }

                tlv_print(tag, v);
                tlv_obj obj{tag, std::move(v)};
                insert(std::move(obj));
            }
            return true;
        };

        AC_TYPE ac_type;
        struct {
            uint8_t cda : 1;
        } oda_status;
        std::set<uint32_t> tags_to_read_yet;
        tlv_obj_list tags_to_write_yet_after_gen_ac;
        tlv_obj_list tags_to_write_yet_before_gen_ac;
        std::vector<uint8_t> afl;
        std::vector<uint8_t> contactless_transaction_limit;
        std::vector<uint8_t> static_oda_data;
        std::vector<uint8_t> saved_gac_rsp;
        const uint8_t* active_afl;
        uint8_t next_record;

        void init_card_read() {
            active_afl = afl.data();
            pr_debug("sfi ", static_cast<int>(AFL_94.get_sfi(active_afl)),
                     " first ", static_cast<int>(AFL_94.get_first_record(active_afl)),
                     " last ",
                     AFL_94.get_last_record(active_afl),
                     "\n");

            next_record = AFL_94.get_first_record(active_afl);
        };
        void read_next_record(modulel2* emvl2) {
            uint8_t sfi = AFL_94.get_sfi(active_afl);
            pr_debug("READ RECORD sfi ", (int)sfi, " record #", (int)next_record,
                     " [ ", (int)AFL_94.get_first_record(active_afl),
                     " - ", (int)AFL_94.get_last_record(active_afl), "]\n");
            emvl2->send_apdu(apdu_builder::build(COMMANDS::READ_RECORD).p1(next_record).p2((sfi << 3) | 4).le(0).to_bytes());
        }

        bool is_afl_empty() {
            if (active_afl >= afl.data() + afl.size()) {
                return true;
            }
            return false;
        }

        void get_record_and_move_to_next(bool& signed_record, uint8_t& sfi) {
            sfi = AFL_94.get_sfi(active_afl);
            auto first = AFL_94.get_first_record(active_afl);
            auto oda_num = AFL_94.get_oda_records(active_afl);
            if (first + oda_num > next_record) {
                signed_record = true;
            };

            next_record++;
            if (next_record > AFL_94.get_last_record(active_afl)) {
                active_afl += 4;
                if (!is_afl_empty()) {
                    next_record = AFL_94.get_first_record(active_afl);
                }
            }
        };

        // TODO need to check oda data size etc. and set TVR accordingly
        // refer to S4.35
        bool parse_record(const std::vector<uint8_t>& apdu, bool signed_record, uint8_t sfi) {
            // S4.24
            if (sfi <= 10) {
                if (apdu.size() <= 4 ||
                    apdu[0] != 0x70 ||
                    apdu[1] == 0) {
                    return false;
                }
            }

            auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                if (constructed &&
                    signed_record && oda_status.cda &&
                    tag == 0x70 && sfi <= 10) {
                    std::vector<uint8_t> data{begin, end};
                    pr_debug("APPEND ", data, "\n");
                    std::copy(begin, end, back_inserter(static_oda_data));
                }

                return save_tlv_from_card(tag, begin, end, constructed);
            };

            if (!tlv_visit(apdu.begin(), apdu.end() - 2, parser))
                return false;

            // S4.34 S4.35
            bool oda_err = false;
            if (signed_record && oda_status.cda) {
                if (sfi > 10) {
                    if (apdu[0] == 0x70) {
                        pr_debug("sfi ", static_cast<int>(sfi), " record ", static_cast<int>(next_record), "\n");
                        std::vector<uint8_t> data{apdu.begin(), apdu.end() - 2};
                        pr_debug("APPEND ", data, "\n");

                        std::copy(apdu.begin(), apdu.end() - 2, back_inserter(static_oda_data));
                    } else {
                        oda_err = true;
                    }
                }

#if 0
                if (static_oda_data.size() >= 254) { // FIXME
                    oda_err = true;
                }
#endif
                if (oda_err) {
                    set_bit(TVR_95, TAG_TVR_95::cda_failed);
                }
            };

            return true;
        };
    };

    const map<uint32_t, std::vector<uint8_t>> DEFAULT_CONFIG_DATA{
        // additional terminal capabilities
        {0x9F40, {0x00, 0x00, 0x00, 0x00, 0x00}},
        // application versio number (reader)
        {0x9F09, {0x00, 0x02}},
        // card data input capability
        {0xDF8117, {0x00}},
        //cvm capability - cvm required,
        {0xDF8118, {0x00}},
        //cvm capability - no cvm required
        {0xDF8119, {0x00}},
        //default udol
        {0xDF8111A, {0x9F, 0x6A, 0x04}},
        //hold time value
        {0xDF8130, {0x0D}},
        //kernel configuration
        {0xDF811B, {0x00}},
        //kernel id
        {0xDF810C, {0x02}},
        //MS application version number (reader)
        {0x9F6D, {0x00, 0x01}},
        //MS cvm capability - cvm required
        {0xDF811E, {0xF0}},
        //MS cvm capability - no cvm required
        {0xDF812C, {0xF0}},
        //max lifetime of torn transaction log record
        {0xDF811C, {0x01, 0x2c}},
        // max numberof torn records
        {0xDF811D, {0x00}},
        // message hold time
        {0xDF812D, {0x00, 0x00, 0x13}},
        // max relay resistence grace period
        {0xDF8133, {0x00, 0x32}},
        // min relay resistence grace period
        {0xDF8132, {0x00, 0x14}},
        //phone message table see table 4.4
        {0xDF8131,
         {0x00, 0x00, 0x01, 0x00, 0x00, 0x01, /* SEE PHONE */ 0x20, /* NOT READY */ 0x00,
          0x00, 0x08, 0x00, 0x00, 0x08, 0x00, /* SEE PHONE */ 0x20, /* NOT READY */ 0x00,
          0x00, 0x04, 0x00, 0x00, 0x04, 0x00, /* SEE PHONE */ 0x20, /* NOT READY */ 0x00,
          0x00, 0x01, 0x00, 0x00, 0x01, 0x00, /* SEE PHONE */ 0x20, /* NOT READY */ 0x00,
          0x00, 0x02, 0x00, 0x00, 0x02, 0x00, /* SEE PHONE */ 0x20, /* NOT READY */ 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*  DECLINED */ 0x07, /* NOT READY */ 0x00}},
        // reader contactles floor limit
        {0xDF8123, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
        // reader contactless transaction limit (no od-cvm)
        {0xDF8124, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
        // reader contactless transaction limit (od-cvm)
        {0xDF8125, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
        // reader cvm required limit
        {0xDF8126, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
        //relay resistance accurancy threshold
        {0xDF8136, {0x01, 0x2C}},
        //relay resistance transmission time mismatch theshold
        {0xDF8137, {0x32}},
        //security capability
        {0xDF811F, {0x00}},
        //TAC-Default
        {0xDF8120, {0x84, 0x00, 0x00, 0x00, 0x0C}},
        //TAC-Denial
        {0xDF8121, {0x84, 0x00, 0x00, 0x00, 0x0C}},
        //TAC-Online
        {0xDF8122, {0x84, 0x00, 0x00, 0x00, 0x0C}},
        // terminal country code
        {0x9F1A, {0x00, 0x00}},
        // terminal expected transmission time for RR C-APDU
        {0xDF8134, {0x00, 0x12}},
        // terminal expected transmission time for RR R-APDU
        {0xDF8135, {0x00, 0x18}},
        // terminal type
        {0x9F35, {0x00}},
        // time out value
        {0xDF8127, {0x01, 0xF4}},
        // transaction type
        {0x9C, {0x00}}};

private:
    modulel2* emvl2;
    database kernel_db;
    const candidate* candy;
    int failed_ms_cntr;

private:
    enum class SIGNAL : uint8_t {
        KERNEL_START,
        DET,
        RA,
        ACT,
        STOP,
        CLEAN,
        TIMEOUT,
        L1RSP
    };

    std::string to_string(SIGNAL sig) {
        switch (sig) {
        case SIGNAL::KERNEL_START:
            return "KERNEL_START";
        case SIGNAL::DET:
            return "DET";
        case SIGNAL::RA:
            return "RA";
        case SIGNAL::ACT:
            return "ACT";
        case SIGNAL::STOP:
            return "STOP";
        case SIGNAL::CLEAN:
            return "CLEAN";
        case SIGNAL::TIMEOUT:
            return "TIMEOUT";
        case SIGNAL::L1RSP:
            return "L1RSP";
        default:
            return std::string{};
        };
    };

    enum class KSTATUS : uint8_t {
        DEFAULT = 0,
        EXIT_KERNEL = 1
    };

    enum class NEXT_CMD : uint8_t {
        NONE,
        GET_DATA,
        READ_RECORD
    };

public:
    kernel2(modulel2* emvl2) : emvl2{emvl2}, failed_ms_cntr{0}, state{nullptr}, k2resp{k2responder{this}} {};

    class k2responder : public modulel2::responder {
    public:
        k2responder(kernel2* k2) : modulel2::responder{0, k2->emvl2}, k2{k2} {};
        virtual void handle_apdu(const std::vector<uint8_t>& apdu) override {
            modulel2::responder::handle_apdu(apdu);
            k2->dispatch_signal(SIGNAL::RA, &apdu);
        };

        virtual void handle_det(const std::vector<uint8_t>& data) override {
            k2->dispatch_signal(SIGNAL::DET, &data);
        };

        virtual void handle_l1rsp(const std::vector<uint8_t>& error) override {
            k2->dispatch_signal(SIGNAL::L1RSP, &error);
        };

        virtual void timeout() override {
            k2->dispatch_signal(SIGNAL::TIMEOUT, nullptr);
        };

        virtual void enter() override{};
        virtual void exit() override {}

        kernel2* k2;
    };

    virtual bool start(uint8_t sw1, uint8_t sw2, const tlv_db fci, const candidate* candy, const issuer_script script, modulel2* l2) override {
        (void)sw1;
        (void)sw2;
        pr_debug("starting kernel2\n");
        emvl2 = l2;
        this->candy = candy;

        if (script.size() != 0) {
            pr_debug("issuer script update\n");
        } else if (fci.has_tag(IDSD_D2) && candy->extended_selection.size() != 0) {
            pr_debug("IDS procesing\n");
        } else {
            pr_debug("New transaction\n");
            kernel_db = database{};
            kernel_db.emplace(ADF_NAME_4F.id, candy->adf_name);
            if (candy->extended_selection.size() != 0)
                kernel_db.emplace(EXTENDED_SELECTION_9F29.id, candy->extended_selection);
            auto combo = candy->combo;

            // TODO perhaps we should do these consolidation at intialization time
            //pr_debug("kernel_db :\n");
            //kernel_db.print();
            kernel_db.insert(emvl2->l2_cfgs.terminal_cfg);
            //pr_debug("terminal db\n");
            //emvl2->l2_cfgs.terminal_cfg.print();
            kernel_db.update(combo->krn->db);
            //pr_debug("krn db\n");
            //combo->krn->db.print();
            kernel_db.update(combo->app->db);
            //pr_debug("application db\n");
            //combo->app->db.print();
            kernel_db.update(combo->transact->db);
            //pr_debug("transact db\n");
            //combo->transact->db.print();
            kernel_db.update(combo->db);
            //pr_debug("combo db\n");
            //combo->db.print();
            kernel_db.insert(fci);
            //pr_debug("fci db\n");
            //fci.print();
            emvl2->set_state(&k2resp);
            enter_state(&ks);
            dispatch_signal(SIGNAL::KERNEL_START);
            dispatch_signal(SIGNAL::ACT);
        }
        return true;
    }

private:
    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)>* state;
    k2responder k2resp;

    void enter_state(std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)>* next) {
        state = next;
    };

    void dispatch_signal(SIGNAL sig, const std::vector<uint8_t>* param = nullptr) {
        if (state != nullptr) {
            pr_debug("Kernel Signal -> ", to_string(sig), "\n");
            auto ret = (*state)(sig, param);
            if (ret == KSTATUS::EXIT_KERNEL) {
                // TODO
                kernel_db.clear();
            }
        } else {
            pr_error("dispatch signal when there is NO handler\n");
        }
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> ks = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        if (sig == SIGNAL::KERNEL_START) {
            pr_debug("initialize default config data\n");
            for (auto& p : DEFAULT_CONFIG_DATA) {
                if (!kernel_db.has_tag(p.first)) {
                    tlv_print(p.first, p.second);
                    tlv_obj obj{p.first, p.second};
                    kernel_db.insert(std::move(obj));
                }
            }

            // 6.2.3
            kernel_db.emplace(MOBILE_SUPPORT_INDICATOR_9F7E.id, std::vector<uint8_t>{0x01});

            // outcome params
            std::vector<uint8_t> params = TAG_OUTCOME_PARAMETER_SET_DF8129::get_default();
            v_set_bit(params, TAG_OUTCOME_PARAMETER_SET_DF8129::discretionary_data_present);
            tlv_obj obj{OUTCOME_PARAMETER_SET_DF8129.id, std::move(params)};
            kernel_db.insert(std::move(obj));

            // ui data
            std::vector<uint8_t> ui = TAG_USER_INTERFACE_REQUEST_DATA_DF8116::get_default();
            auto& hold_time = kernel_db[MESSAGE_HOLD_TIME_DF812D];
            TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_hold_time(ui, hold_time);
            kernel_db.emplace(USER_INTERFACE_REQUEST_DATA_DF8116.id, std::move(ui));

            // error indication
            std::vector<uint8_t> error = TAG_ERROR_INDICATION_DF8115::get_default();
            kernel_db.emplace(ERROR_INDICATION_DF8115.id, std::move(error));

            enter_state(&s1_idle);
        };

        return KSTATUS::DEFAULT;
    };

    void remove_records(){};

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s1_idle = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        switch (sig) {
        case SIGNAL::ACT: // S1_1
            break;
        case SIGNAL::STOP: { // S1_2
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .initialize(DISCRETIONARY_DATA_FF8106)
                                        .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::CLEAN: // S1_4
            remove_records();
            return KSTATUS::EXIT_KERNEL;
        default:
            return KSTATUS::DEFAULT;
        };

        //s1_7
        if (param != nullptr) {
            auto parser = [&](uint32_t tag, auto begin, auto end, bool combined) mutable -> bool {
                if (!combined) {
                    std::vector<uint8_t> v{begin, end};
                    tlv_obj obj{tag, std::move(v)};
                    if (tag_has_permission(tag, PERM_ACT)) {
                        kernel_db.update(obj);
                    };
                };
                return true;
            };
            tlv_visit(param->begin(), param->end(), parser);
        };

        if (kernel_db.has_non_empty_tag(LANG_PREF_5F2D)) {
            auto v = kernel_db[LANG_PREF_5F2D];
            if (v.size() < LANG_PREF_5F2D.maxlen) {
                v.resize(LANG_PREF_5F2D.maxlen);
            };
            auto& p = kernel_db[USER_INTERFACE_REQUEST_DATA_DF8116];
            TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_lang_pref(p, v);
        };

        if (!kernel_db.has_tag(DF_NAME_84) || kernel_db.has_empty_tag(DF_NAME_84.id)) {
            auto& error_ind = kernel_db[ERROR_INDICATION_DF8115.id];
            TAG_ERROR_INDICATION_DF8115::set_l2_error(error_ind, L2_ERROR::CARD_DATA_MISSING);

            //s_8:
            auto& outcome = kernel_db[OUTCOME_PARAMETER_SET_DF8129];
            TAG_OUTCOME_PARAMETER_SET_DF8129::set_status(outcome, OUTCOME_TYPE::SELECT_NEXT);
            TAG_OUTCOME_PARAMETER_SET_DF8129::set_start(outcome, RESTART_POINT::C);
            auto tlv = kernel_db.to_tlv(ERROR_INDICATION_DF8115);

            tlv_obj discretionary_data(DISCRETIONARY_DATA_FF8106.id, tlv);
            kernel_db.insert(std::move(discretionary_data));
            return KSTATUS::EXIT_KERNEL;
        };

        if (kernel_db.has_non_empty_tag(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D)) {
            if (kernel_db.get_bit(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D,
                                  KERNEL2::TAG_APPLICATION_CAPABILITIES_INFO_9F5D::support_for_field_off_detection)) {
                auto& v = kernel_db[OUTCOME_PARAMETER_SET_DF8129.id];
                auto& hold_time = kernel_db[HOLD_TIME_VALUE_DF8130];
                TAG_OUTCOME_PARAMETER_SET_DF8129::set_field_off(v, hold_time[0]);
            };
        };

        //s1_9:
        kernel_db.initialize(CVM_RESULT_9F34);
        kernel_db.ac_type = AC_TYPE::TC;
        kernel_db.initialize(TVR_95);
        kernel_db.oda_status = {0};
        kernel_db.initialize(RRP_COUNTER_DF8307);
        kernel_db.initialize(TERMINAL_CAPABILITIES_9F33);
        auto& cap = kernel_db[TERMINAL_CAPABILITIES_9F33];
        cap[0] = kernel_db[CARD_DATA_INPUT_CAPABILITY_DF8117][0];
        cap[1] = 0;
        cap[2] = kernel_db[SECURITY_CAPABILITY_DF811F][0];

        // s1_10
        kernel_db.initialize(DATA_NEEDED_DF8106);
        kernel_db.initialize(DATA_TO_SEND_FF8104);
        auto& data_needed = kernel_db[DATA_NEEDED_DF8106];

        if (kernel_db.has_non_empty_tag(TAGS_TO_READ_DF8112)) {
            tag_list_deserialize(kernel_db[TAGS_TO_READ_DF8112.id],
                                 kernel_db.tags_to_read_yet);
        }

        if (kernel_db.has_empty_tag(TAGS_TO_READ_DF8112.id)) {
            auto tag = tag_in_bytes(TAGS_TO_READ_DF8112.id);
            std::copy(tag.begin(), tag.end(), std::back_inserter(data_needed));
        };

        // s1_11
        std::vector<uint8_t> pdol_list{};
        bool pdol_data_missing = false;

        if (kernel_db.has_tag(PDOL_9F38))
            pdol_data_missing = !build_dol(PDOL_9F38.id, kernel_db[PDOL_9F38], kernel_db, pdol_list, data_needed);

        if (!pdol_data_missing) {
            // s1_13
            kernel_db.insert(tlv_obj{PDOL_RELATED_DATA_DF8111.id, pdol_list});
            pdol_list = make_tlv(0x83, pdol_list);
            emvl2->send_apdu(apdu_builder::build(COMMANDS::GPO).data(pdol_list).le(0).to_bytes());
        }

        // S1_15
        drain_tags_to_read_yet();
        auto& data_to_send = kernel_db[DATA_TO_SEND_FF8104];

        // s1_16
        kernel_db.initialize(IDS_STATUS_DF8128);
        kernel_db.initialize(DS_SUMMARY_STATUS_DF810B);
        kernel_db.initialize(POST_GEN_AC_PUT_DATA_STATUS_DF810E);
        kernel_db.initialize(PRE_GEN_AC_PUT_DATA_STATUS_DF810F);
        kernel_db.initialize(DS_DIGEST_H_DF61);
        kernel_db.tags_to_write_yet_after_gen_ac.initialize();
        kernel_db.tags_to_write_yet_before_gen_ac.initialize();

        if (kernel_db.has_non_empty_tag(TAGS_TO_WRITE_BEFORE_GEN_AC_FF8102)) {
            kernel_db.tags_to_write_yet_before_gen_ac.append(kernel_db[TAGS_TO_WRITE_BEFORE_GEN_AC_FF8102]);
        }

        if (kernel_db.has_non_empty_tag(TAGS_TO_WRITE_AFTER_GEN_AC_FF8103)) {
            kernel_db.tags_to_write_yet_after_gen_ac.append(kernel_db[TAGS_TO_WRITE_AFTER_GEN_AC_FF8103]);
        }

        if (kernel_db.has_empty_tag(TAGS_TO_WRITE_BEFORE_GEN_AC_FF8102.id)) {
            auto tag = tag_in_bytes(TAGS_TO_WRITE_BEFORE_GEN_AC_FF8102.id);
            std::copy(tag.begin(), tag.end(), std::back_inserter(data_needed));
        }

        if (kernel_db.has_empty_tag(TAGS_TO_WRITE_AFTER_GEN_AC_FF8103.id)) {
            auto tag = tag_in_bytes(TAGS_TO_WRITE_AFTER_GEN_AC_FF8103.id);
            std::copy(tag.begin(), tag.end(), std::back_inserter(data_needed));
        }

        if (kernel_db.has_non_empty_tag(DSVN_TERM_DF810D) &&
            kernel_db.has_tag(DS_REQUESTED_OPERATOR_ID_9F5C)) {
            // s1_18
            if (kernel_db.has_tag(DS_ID_9F5E)) {
                auto tlv = kernel_db.to_tlv(DS_ID_9F5E);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            } else {
                auto tlv = make_tlv(DS_ID_9F5E.id, std::vector<uint8_t>(1));
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            }

            if (kernel_db.has_tag(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D)) {
                auto tlv = kernel_db.to_tlv(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            } else {
                auto tlv = make_tlv(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D.id, std::vector<uint8_t>(1));
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            };

            // s1_19
            if (kernel_db.has_non_empty_tag(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D) &&
                kernel_db.has_non_empty_tag(DS_ID_9F5E)) {
                auto& v = kernel_db[KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D];
                auto version = KERNEL2::TAG_APPLICATION_CAPABILITIES_INFO_9F5D::get_ds_version(v);
                if (version == 1 || version == 2) {
                    // s1_20
                    kernel_db.set_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read);
                };
            };
        }

        // s1_21
        if (pdol_data_missing) {
            // s1_22
            send_dek();
            // s1_23
            enter_state(&s2_wait_for_pdol_data);
            start_time_out();
        } else {
            enter_state(&s3_wait_for_gpo_resp);
        }

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s3_wait_for_gpo_resp = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        switch (sig) {
        case SIGNAL::RA: {
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                //S3.9.1, 2
                pr_debug("gpo response failure\n");
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::SELECT_NEXT)
                                            .field_off()
                                            .start(RESTART_POINT::C)
                                            .error(sw1, sw2)
                                            .initialize(DISCRETIONARY_DATA_FF8106)
                                            .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            } else {
                // s3.10
                auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                    if (tag == 0x80) { // format 1, always AIP (2 bytes) + AFL
                        if (end - begin >= 2) {
                            auto p = begin + 2;
                            return kernel_db.save_tlv_from_card(AIP_82.id, begin, p, false) &&
                                   kernel_db.save_tlv_from_card(AFL_94.id, p, end, false);
                        } else {
                            return false;
                        };
                    } else {
                        return kernel_db.save_tlv_from_card(tag, begin, end, constructed);
                    };
                };

                if (!tlv_visit(apdu.begin(), apdu.end() - 2, parser)) {
                    // s3.12
                    outcome_builder builder{kernel_db};
                    emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                                .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                                .ui_on_outcome()
                                                .error(L2_ERROR::PARSING_ERROR)
                                                .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                                .initialize(DISCRETIONARY_DATA_FF8106)
                                                .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                                .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                .pack(DISCRETIONARY_DATA_FF8106)
                                                .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                .post());

                    return KSTATUS::EXIT_KERNEL;
                } else if (!kernel_db.has_tag(AIP_82) || !kernel_db.has_tag(AFL_94)) {
                    // s3.14
                    outcome_builder builder{kernel_db};
                    emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                                .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                                .ui_on_outcome()
                                                .error(L2_ERROR::CARD_DATA_MISSING)
                                                .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                                .initialize(DISCRETIONARY_DATA_FF8106)
                                                .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                                .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                .pack(DISCRETIONARY_DATA_FF8106)
                                                .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                .post());
                    return KSTATUS::EXIT_KERNEL;
                };

                auto& kcfg = kernel_db[KERNEL_CONFIGURATION_DF811B];
                pr_debug("current kernel config\n");
                dump(KERNEL_CONFIGURATION_DF811B, kcfg);
                pr_debug("aip\n");
                dump(AIP_82, kernel_db[AIP_82]);

                // s3.15
                if (!v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::emv_mode_contactless_not_supported)) {
                    // s3.16
                    auto& aip = kernel_db[AIP_82];
                    if (v_get_bit(aip, TAG_AIP_82::emv_mode_supported)) {
                        return handle_emv_mode();
                    }
                }
                if (v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::magstripe_mode_contactless_not_supported)) {
                    outcome_builder builder{kernel_db};
                    emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                                .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                                .ui_on_outcome()
                                                .error(L2_ERROR::MS_NOT_SUPPORTED)
                                                .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                                .initialize(DISCRETIONARY_DATA_FF8106)
                                                .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                                .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                .pack(DISCRETIONARY_DATA_FF8106)
                                                .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                .post());
                    return KSTATUS::EXIT_KERNEL;
                } else {
                    return handle_ms_mode();
                }
            };

            break;
        };
        case SIGNAL::STOP: {
            // S3.7
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .initialize(DISCRETIONARY_DATA_FF8106)
                                        .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::DET:
            // S3.3
            kernel_db.update_with_det_data(*param);
            break;
        case SIGNAL::L1RSP: {
            //S3.5
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::TRY_AGAIN)
                                        .start(RESTART_POINT::B)
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .initialize(DISCRETIONARY_DATA_FF8106)
                                        .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    // s3.30
    KSTATUS handle_emv_mode() {
        pr_debug("handling EMV mode\n");
        std::vector<uint8_t> default_one{0x08, 0x01, 0x01, 0x00};
        auto& afl = kernel_db[AFL_94];
        auto& aip = kernel_db[AIP_82];
        auto& kcfg = kernel_db[KERNEL_CONFIGURATION_DF811B];

        if (afl.size() >= 4 &&
            (std::vector<uint8_t>(afl.begin(), afl.begin() + 4) == default_one) &&
            !v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::magstripe_mode_contactless_not_supported)) {
            //S3.32
            kernel_db.afl = std::vector<uint8_t>(afl.cbegin() + 4, afl.cend());
        } else {
            //S3.31
            kernel_db.afl = afl;
        }

        if (v_get_bit(aip, TAG_AIP_82::on_device_cardholder_verification_supported) &&
            v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::on_device_verification_supported)) {
            kernel_db.contactless_transaction_limit = kernel_db[READER_CONTACTLESS_TRANSACTION_LIMIT_ON_DEVICE_CVM_DF8125];
        } else {
            kernel_db.contactless_transaction_limit = kernel_db[READER_CONTACTLESS_TRANSACTION_LIMIT_NO_ON_DEVICE_CVM_DF8124];
        };

        if (v_get_bit(aip, TAG_AIP_82::rrp_supported) &&
            v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::rrp_supported)) {
            return send_rrp_data();
        }

        auto& tvr = kernel_db[TVR_95];
        TAG_TVR_95::set_rrp(tvr, TAG_TVR_95::RRP_STATUS::NOT_PERFORMED);
        return s3R1();
    };

    KSTATUS s3R1() {
        auto active_tag = kernel_db.tags_to_read_yet.begin();
        if (active_tag == kernel_db.tags_to_read_yet.end()) {
            // READ Data
            if (kernel_db.afl.size() == 0) {
                // S3R1.6
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                            .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                            .ui_on_outcome()
                                            .error(L2_ERROR::CARD_DATA_ERROR)
                                            .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                            .initialize(DISCRETIONARY_DATA_FF8106)
                                            .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            }
            kernel_db.init_card_read();
            kernel_db.read_next_record(emvl2);
            enter_state(&s4_wait_for_emv_read_record);
        } else {
            // GET Data
            uint8_t p1 = static_cast<uint8_t>((*active_tag >> 8) & 0xFF);
            uint8_t p2 = static_cast<uint8_t>((*active_tag) & 0xFF);
            emvl2->send_apdu(apdu_builder::build(COMMANDS::GET_DATA).p1(p1).p2(p2).le(0).to_bytes());
            enter_state(&s5_wait_for_get_data);
        };

        // TODO
        // S3R1.10
        if (kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
            auto& data_to_send = kernel_db[DATA_TO_SEND_FF8104];
            if (kernel_db.has_non_empty_tag(DS_SLOT_AVAILABILITY_9F5F)) {
                auto tlv = kernel_db.to_tlv(DS_SLOT_AVAILABILITY_9F5F);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            }
            if (kernel_db.has_non_empty_tag(DS_SUMMARY_1_9F7D)) {
                auto tlv = kernel_db.to_tlv(DS_SUMMARY_1_9F7D);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            }
            if (kernel_db.has_non_empty_tag(DS_UNPREDICTABLE_NUMBER_9F7F)) {
                auto tlv = kernel_db.to_tlv(DS_UNPREDICTABLE_NUMBER_9F7F);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            }
            if (kernel_db.has_non_empty_tag(DS_SLOT_MANAGEMENT_CONTROL_9F6F)) {
                auto tlv = kernel_db.to_tlv(DS_SLOT_MANAGEMENT_CONTROL_9F6F);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            }
            if (kernel_db.has_tag(DS_ODS_CARD_9F54)) {
                auto tlv = kernel_db.to_tlv(DS_ODS_CARD_9F54);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
            }
            auto tlv = kernel_db.to_tlv(UNPREDICTABLE_NUMBER_9F37);
            std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));

            if ((kernel_db.has_non_empty_tag(DS_SLOT_AVAILABILITY_9F5F) &&
                 kernel_db.has_non_empty_tag(DS_SUMMARY_1_9F7D) &&
                 kernel_db.has_non_empty_tag(DS_UNPREDICTABLE_NUMBER_9F7F) &&
                 !kernel_db.has_tag(DS_ODS_CARD_9F54)) ||
                (kernel_db.has_non_empty_tag(DS_SUMMARY_1_9F7D) &&
                 kernel_db.has_tag(DS_ODS_CARD_9F54))) {
                // goto S3R1.14
            } else {
                //S3R1.13
                kernel_db.clear_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read);
            }
        }

        //S3R1.14
        drain_tags_to_read_yet();

        if (kernel_db.has_non_empty_tag(DATA_NEEDED_DF8106) ||
            (kernel_db.has_non_empty_tag(DATA_TO_SEND_FF8104) &&
             kernel_db.tags_to_read_yet.size() == 0)) {
            // S3R1.16
            send_dek();
        }

        // S3R1.17, 18
        if ((kernel_db.get_bit(AIP_82, TAG_AIP_82::cda_supported) &&
             kernel_db.get_bit(TERMINAL_CAPABILITIES_9F33, TAG_TERMINAL_CAPABILITIES_9F33::cda)) ||
            kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
            // S3R1.19
            pr_debug("oda status, set cda required\n");
            kernel_db.oda_status.cda = 1;
        } else {
            // S3R1.20
            kernel_db.set_bit(TVR_95, TAG_TVR_95::oda_not_performed);
        }

        return KSTATUS::DEFAULT;
    };

    void drain_tags_to_read_yet(bool send_empty = false) {
        auto& data_to_send = kernel_db[DATA_TO_SEND_FF8104];
        std::vector<uint32_t> to_remove{};
        for (auto tag : kernel_db.tags_to_read_yet) {
            if (kernel_db.has_non_empty_tag(tag)) {
                auto tlv = kernel_db.to_tlv(tag);
                pr_debug("data to send : ", tlv, "\n");
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
                to_remove.push_back(tag);
            } else if (send_empty && find_tag_info(tag) != nullptr) {
                auto tlv = make_tlv(tag, std::vector<uint8_t>{});
                pr_debug("data to send : ", tlv, "\n");
                std::copy(tlv.begin(), tlv.end(), back_inserter(data_to_send));
                to_remove.push_back(tag);
            }
        };
        for (auto t : to_remove) {
            auto p = kernel_db.tags_to_read_yet.find(t);
            kernel_db.tags_to_read_yet.erase(p);
        }
    };

    static inline int get_num_of_bit_one(const vector<uint8_t>& v) {
        int ret = 0;
        auto ptr = v.data();
        auto size = v.size();

        while (size--) {
            uint8_t byte = *ptr++;
            uint8_t mask = 0x80;
            while (mask) {
                if (byte & mask)
                    ret++;
                mask >>= 1;
            }
        }

        return ret;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s5_wait_for_get_data = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s7_wait_for_ms_read_record = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        switch (sig) {
        case SIGNAL::RA: { // S7.9
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                pr_debug("read record response failure\n");
                // S7.10.1, 2
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                            .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                            .ui_on_outcome()
                                            .error(sw1, sw2)
                                            .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                            .create_ms_dd<KERNEL2_NS>()
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            } else {
                // S7.11
                uint8_t sfi = 0;
                bool signed_record = false;
                kernel_db.get_record_and_move_to_next(signed_record, sfi);

                // S7.12
                bool parse_result = kernel_db.parse_record(apdu, signed_record, sfi);
                if (!parse_result) {
                    // S7.13.1
                    outcome_builder builder{kernel_db};
                    emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                                .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                                .ui_on_outcome()
                                                .error(L2_ERROR::PARSING_ERROR)
                                                .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                                .create_ms_dd<KERNEL2_NS>()
                                                .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                .pack(DISCRETIONARY_DATA_FF8106)
                                                .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                .post());
                    return KSTATUS::EXIT_KERNEL;
                }

                // S7.14
                if (kernel_db.has_non_empty_tag(KERNEL2::UDOL_9F69)) {
                    // S7.15
                    check_dol_if_needed(KERNEL2::UDOL_9F69);
                }

                // S7.16, 17
                if (!kernel_db.is_afl_empty()) {
                    // S7.18, 19
                    kernel_db.read_next_record(emvl2);
                    break;
                }

                // S7.20
                if (!(kernel_db.has_non_empty_tag(TRACK2_DATA_9F6B) &&
                      kernel_db.has_non_empty_tag(KERNEL2::PUNATC_TRACK2_9F66) &&
                      kernel_db.has_non_empty_tag(PCVC3_TRACK2_9F65) &&
                      kernel_db.has_non_empty_tag(NATC_TRACK2_9F67))) {
                    // S7.21.1,2
                    outcome_builder builder{kernel_db};
                    emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                                .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                                .ui_on_outcome()
                                                .error(L2_ERROR::CARD_DATA_MISSING)
                                                .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                                .create_ms_dd<KERNEL2_NS>()
                                                .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                .pack(DISCRETIONARY_DATA_FF8106)
                                                .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                .post());
                    return KSTATUS::EXIT_KERNEL;
                };

                // S7.22
                int nUN = get_num_of_bit_one(kernel_db[KERNEL2::PUNATC_TRACK2_9F66]) -
                          kernel_db[NATC_TRACK2_9F67][0];
                bool error = false;
                if (nUN < 0 || nUN > 8) {
                    // GOTO S7.24.1
                    error = true;
                } else if (kernel_db.has_non_empty_tag(TRACK1_DATA_56)) {
                    if ((!kernel_db.has_tag(NATC_TRACK1_9F64) ||
                         kernel_db.has_empty_tag(NATC_TRACK1_9F64)) ||
                        (!kernel_db.has_tag(PCVC3_TRACK1_9F62) ||
                         kernel_db.has_empty_tag(PCVC3_TRACK1_9F62)) ||
                        (!kernel_db.has_tag(PUNATC_TRACK1_9F63) ||
                         kernel_db.has_empty_tag(PUNATC_TRACK1_9F63)) ||
                        (get_num_of_bit_one(kernel_db[PUNATC_TRACK1_9F63]) - kernel_db[NATC_TRACK1_9F64][0] != nUN)) {
                        error = true;
                    }
                }

                if (error) {
                    // S7.24.1
                    outcome_builder builder{kernel_db};
                    emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                                .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                                .ui_on_outcome()
                                                .error(L2_ERROR::CARD_DATA_ERROR)
                                                .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                                .create_ms_dd<KERNEL2_NS>()
                                                .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                .pack(DISCRETIONARY_DATA_FF8106)
                                                .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                .post());

                    return KSTATUS::EXIT_KERNEL;
                }

                // S7.23
                TAG_TRACK2_DATA_9F6B::track_data data{};
                TAG_TRACK2_DATA_9F6B::parse(kernel_db[TRACK2_DATA_9F6B], data);
                pr_debug("track 2 data ", kernel_db[TRACK2_DATA_9F6B], " parsed dd : ",
                         data.discretionary_data, "\n");
                kernel_db.insert(tlv_obj(DD_CARD_TRACK2_DF812B.id, TRACK2_COMMON::discretionary_data_to_bytes(data.discretionary_data)));

                if (kernel_db.has_non_empty_tag(TRACK1_DATA_56)) {
                    TAG_TRACK1_DATA_56::track_data tmp{};
                    TAG_TRACK1_DATA_56::parse(kernel_db[TRACK1_DATA_56], tmp);
                    kernel_db.insert(tlv_obj(DD_CARD_TRACK1_DF812A.id, tmp.discretionary_data));
                }
                return s78();
            };
        };
        case SIGNAL::STOP: {
            // S4.7, 8
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .create_ms_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::DET: // S7.1
                          // S7.2
            kernel_db.update_with_det_data(*param);
            break;
        case SIGNAL::L1RSP: { // S7.4
            // S7.5, 6
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .ui_on_outcome()
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_ms_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        default:
            break;
        };
        return KSTATUS::DEFAULT;
    };

    KSTATUS s78() {
        // S78.1
        if (kernel_db.has_empty_tag(PROCEED_TO_FIRST_WRITE_FLAG_DF8110)) {
            // S78.2
            pr_debug("PROCEED_TO_FIRST_WRITE_FLAG_DF8110 is empty\n");
            auto& data_needed = kernel_db[DATA_NEEDED_DF8106];
            auto tag = tag_in_bytes(PROCEED_TO_FIRST_WRITE_FLAG_DF8110.id);
            std::copy(tag.begin(), tag.end(), std::back_inserter(data_needed));
        } else if (!(kernel_db.has_tag(PROCEED_TO_FIRST_WRITE_FLAG_DF8110) && // S78.7
                     kernel_db[PROCEED_TO_FIRST_WRITE_FLAG_DF8110][0] == 0)) {
            // S78.8
            if (kernel_db.has_non_empty_tag(AMOUNT_AUTHORISED_9F02)) {
                // S78.10
                auto value = kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
                auto limit = tag_n::to_numeric_value(kernel_db.contactless_transaction_limit);
                if (value > limit) {
                    // S78.11
                    outcome_builder builder{kernel_db};
                    emvl2->generate_outcome(builder.status(OUTCOME_TYPE::SELECT_NEXT)
                                                .start(RESTART_POINT::C)
                                                .error(L2_ERROR::MAX_LIMIT_EXCEEDED)
                                                .create_ms_dd<KERNEL2_NS>()
                                                .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                .pack(DISCRETIONARY_DATA_FF8106)
                                                .post());

                    return KSTATUS::EXIT_KERNEL;
                }

                // S78.12
                drain_tags_to_read_yet(true);

                // S78.13
                if (kernel_db.has_non_empty_tag(DATA_TO_SEND_FF8104)) {
                    // S78.14
                    // potentially FIXME: on spec, it's only handling data_to_send
                    // not data_needed
                    send_dek();
                }

                // S78.15
                std::vector<uint8_t> randoms(4);
                get_randoms(randoms.data(), randoms.size());
                pr_debug("generated UNPREDICTABLE_NUMBER_NUMERIC_9F6A : ", randoms, "\n");
                // convent to bcd
                std::vector<uint8_t> bcd = to_bcd(randoms);
                bcd.resize(randoms.size());
                std::copy(bcd.begin(), bcd.end(), randoms.begin());
                randoms[0] &= 0x0F;
                pr_debug("bcd UNPREDICTABLE_NUMBER_NUMERIC_9F6A : ", randoms, "\n");
                kernel_db.update(tlv_obj(UNPREDICTABLE_NUMBER_NUMERIC_9F6A.id,
                                         std::move(randoms)));

                pr_debug("check on device verification\n");
                auto& aip = kernel_db[AIP_82];
                auto& kcfg = kernel_db[KERNEL_CONFIGURATION_DF811B];
                if (v_get_bit(aip, TAG_AIP_82::on_device_cardholder_verification_supported) &&
                    v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::on_device_verification_supported)) {
                    // S78.19
                    auto value = kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
                    auto limit = tag_n::to_numeric_value(kernel_db[READER_CVM_REQUIRED_LIMIT_DF8126]);
                    if (value > limit) {
                        // S78.20
                        auto& outcome = kernel_db[OUTCOME_PARAMETER_SET_DF8129];
                        TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome, OUTCOME_CVM::CONF_CODE_VERIFIED);
                        kernel_db.set_bit(MOBILE_SUPPORT_INDICATOR_9F7E, TAG_MOBILE_SUPPORT_INDICATOR_9F7E::od_cvm_required);
                        std::vector<uint8_t> udol{};
                        if (kernel_db.has_tag(KERNEL2::UDOL_9F69)) {
                            udol = kernel_db[KERNEL2::UDOL_9F69];
                        } else {
                            udol = kernel_db[DEFAULT_UDOL_DF811A];
                        }
                        std::vector<uint8_t> udol_related_data{};
                        std::vector<uint8_t> missing_tags{};
                        build_dol(KERNEL2::UDOL_9F69.id, udol, kernel_db, udol_related_data, missing_tags);
                        emvl2->send_apdu(apdu_builder::build(COMMANDS::COMPUTE_CRYPTOGRAPHIC_CHECKSUM).data(udol_related_data).le(0).to_bytes());
                        enter_state(&s14_wait_for_ccc_response_2);
                    }
                } else {
                    // S78.17
                    auto udol = kernel_db[KERNEL2::UDOL_9F69];
                    std::vector<uint8_t> udol_related_data{};
                    std::vector<uint8_t> missing_tags{};
                    build_dol(KERNEL2::UDOL_9F69.id, udol, kernel_db, udol_related_data, missing_tags);
                    emvl2->send_apdu(apdu_builder::build(COMMANDS::COMPUTE_CRYPTOGRAPHIC_CHECKSUM).data(udol_related_data).le(0).to_bytes());
                    enter_state(&s13_wait_for_ccc_response_1);
                }

                return KSTATUS::DEFAULT;
            } else {
                // S78.9
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                            .error(L3_ERROR::AMOUNT_NOT_PRESENT)
                                            .create_ms_dd<KERNEL2_NS>()
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            }
        }

        // S78.3
        drain_tags_to_read_yet();

        // S78.4
        if (kernel_db.has_non_empty_tag(DATA_NEEDED_DF8106) ||
            (kernel_db.has_non_empty_tag(DATA_TO_SEND_FF8104) &&
             kernel_db.tags_to_read_yet.size() == 0)) {
            // S78.5
            send_dek();
        }

        // S78.6
        start_time_out();
        enter_state(&s8_wait_for_magstripe_first_write_flag);
        pr_debug("enter s8_wait_for_magstripe_first_write_flag\n");
        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s8_wait_for_magstripe_first_write_flag = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug("enter s8_wait_for_magstripe_first_write_flag\n");
        return KSTATUS::DEFAULT;
    };

    KSTATUS s13_invalid_response(outcome_builder& builder) {
        //S13.30
        // TODO wait for (2^failed_ms_cntr * 300) ms

        //S13.31
        if (++failed_ms_cntr > 5)
            failed_ms_cntr = 5;

        // S13.32, 33
        emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                    .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                    .ui_on_outcome()
                                    .hold(kernel_db[MESSAGE_HOLD_TIME_DF812D])
                                    .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                    .create_ms_dd<KERNEL2_NS>()
                                    .pack(OUTCOME_PARAMETER_SET_DF8129)
                                    .pack(DISCRETIONARY_DATA_FF8106)
                                    .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                    .post());

        return KSTATUS::EXIT_KERNEL;
    };

    void ms_patch_track1_data(uint8_t nUN, uint8_t _nUN){
        // S13.21
        // q := Number of non-zero bits in PCVC3(Track1)
        // t := NATC(Track1)
        auto pcvc3_track1 = kernel_db[PCVC3_TRACK1_9F62];
        int q = get_num_of_bit_one(pcvc3_track1);
        int t = kernel_db[NATC_TRACK1_9F64][0];
        auto cvc3 = to_decimal(kernel_db[CVC3_TRACK1_9F60]);

        // Convert the binary encoded CVC3 (Track1) to the BCD encoding of the
        // corresponding number expressed in base 10. Convert the q least significant digits of
        // the BCD encoded CVC3 (Track1) into ASCII format and copy the q ASCII encoded
        // CVC3 (Track1) characters into the eligible positions of the 'Discretionary Data' in
        // Track 1 Data. The eligible positions are indicated by the q non-zero bits in
        // PCVC3(Track1).
        TAG_TRACK1_DATA_56::track_data data{};
        TAG_TRACK1_DATA_56::parse(kernel_db[TRACK1_DATA_56], data);
        auto src = cvc3.rbegin();
        uint32_t val = vector2int(pcvc3_track1);
        uint32_t mask = 0x01;
        auto dest = data.discretionary_data.rbegin();
        while (q--) {
            while ((val & mask) == 0 && mask) {
                mask <<= 1;
                ++dest;
            };
            *dest++ = static_cast<uint8_t>(*src++);
            mask <<= 1;
        };

        // Convert the BCD encoded Unpredictable Number (Numeric) into ASCII format and
        // replace the nUN least significant eligible positions of the 'Discretionary Data' in Track
        // 1 Data by the nUN least significant characters of the ASCII encoded Unpredictable
        // Number (Numeric). The eligible positions in the 'Discretionary Data' in Track 1 Data
        // are indicated by the nUN least significant non-zero bits in PUNATC(Track1).
        auto un = vector2hex(kernel_db[UNPREDICTABLE_NUMBER_NUMERIC_9F6A]);
        auto punatc_track1 = kernel_db[PUNATC_TRACK1_9F63];
        src = un.rbegin();
        mask = 0x01;
        val = vector2int(punatc_track1);
        dest = data.discretionary_data.rbegin();
        while (nUN--) {
            while ((val & mask) == 0 && mask) {
                mask <<= 1;
                ++dest;
            };
            *dest++ = static_cast<uint8_t>(*src++);
            mask <<= 1;
        };

        // If t != 0, convert the Application Transaction Counter to the BCD encoding of the
        // corresponding number expressed in base 10. Convert the t least significant digits of
        // the BCD encoded Application Transaction Counter into ASCII format. Replace the t
        // most significant eligible positions of the 'Discretionary Data' in Track 1 Data by the t
        // ASCII encoded Application Transaction Counter characters. The eligible positions in
        // the 'Discretionary Data' in Track 1 Data are indicated by the t most significant non-
        // zero bits in PUNATC(Track1).
        if (t != 0) {
            auto atc = to_decimal(kernel_db[ATC_9F36]);
            auto src = atc.end() - t;
            mask = 0x8000;
            auto dest = data.discretionary_data.begin();
            while (t--) {
                while ((val & mask) == 0 && mask) {
                    mask >>= 1;
                    ++dest;
                };
                *dest++ = static_cast<uint8_t>(*src++);
                mask >>= 1;
            };
        }

        // S13.22
        // Convert nUN' into the ASCII format
        // Copy the ASCII encoded nUN' character into the least significant position of the
        // 'Discretionary Data' in Track 1 Data
        data.discretionary_data[data.discretionary_data.size() - 1] = static_cast<uint8_t>(_nUN + '0');
        auto track1_data = TAG_TRACK1_DATA_56::serialize(data);
        kernel_db.update(tlv_obj(TRACK1_DATA_56.id, track1_data));
    };

    void ms_patch_track2_data(uint8_t nUN, uint8_t _nUN) {
        auto pcvc3_track2 = kernel_db[PCVC3_TRACK2_9F65];
        int q = get_num_of_bit_one(pcvc3_track2);
        int t = kernel_db[NATC_TRACK2_9F67][0];
        auto cvc3 = to_decimal(kernel_db[CVC3_TRACK2_9F61]);

        // Convert the binary encoded CVC3 (Track2) to the BCD encoding of the
        // corresponding number expressed in base 10. Copy the q least significant digits of the
        // BCD encoded CVC3 (Track2) in the eligible positions of the 'Discretionary Data' in
        // Track 2 Data. The eligible positions are indicated by the q non-zero bits in
        // PCVC3(Track2).
        TAG_TRACK2_DATA_9F6B::track_data data{};
        TAG_TRACK2_DATA_9F6B::parse(kernel_db[TRACK2_DATA_9F6B], data);
        pr_debug("copy cvc3 ", cvc3, " -> ", data.discretionary_data, "\n");
        pr_debug("according to PCVC3(TRACK2) ", pcvc3_track2, "\n");
        auto src = cvc3.rbegin();
        uint32_t val = vector2int(pcvc3_track2);
        uint32_t mask = 0x01;
        auto dest = data.discretionary_data.rbegin();
        while (q--) {
            while ((val & mask) == 0 && mask) {
                mask <<= 1;
                ++dest;
            };
            *dest++ = *src++;
            mask <<= 1;
        };
        pr_debug("after copy : ", data.discretionary_data, "\n");

        // Replace the nUN least significant eligible positions of the 'Discretionary Data' in
        // Track 2 Data by the nUN least significant digits of Unpredictable Number (Numeric).
        // The eligible positions in the 'Discretionary Data' in Track 2 Data are indicated by the
        // nUN least significant non-zero bits in PUNATC(Track2).
        auto un = vector2hex(kernel_db[UNPREDICTABLE_NUMBER_NUMERIC_9F6A]);
        auto punatc_track2 = kernel_db[KERNEL2::PUNATC_TRACK2_9F66];
        pr_debug("replace ", data.discretionary_data, " by Un : ", un, " according to punatc ", punatc_track2, "\n");
        src = un.rbegin();
        mask = 0x01;
        val = vector2int(punatc_track2);
        dest = data.discretionary_data.rbegin();
        while (nUN--) {
            while ((val & mask) == 0 && mask) {
                mask <<= 1;
                ++dest;
            };
            *dest++ = *src++;
            mask <<= 1;
        };
        pr_debug("after replace : ", data.discretionary_data, "\n");

        // If t != 0, convert the Application Transaction Counter to the BCD encoding of the
        // corresponding number expressed in base 10. Replace the t most significant eligible
        // positions of the 'Discretionary Data' in Track 2 Data by the t least significant digits of
        // the BCD encoded Application Transaction Counter. The eligible positions in the
        // 'Discretionary Data' in Track 2 Data are indicated by the t most significant non-zero
        // bits in PUNATC(Track2).
        if (t != 0) {
            auto atc = to_decimal(kernel_db[ATC_9F36]);
            pr_debug("replace ", data.discretionary_data, " by atc : ", atc, " accorind to puatc ", punatc_track2, "\n");
            auto src = atc.end() - t;
            mask = 0x8000;
            auto dest = data.discretionary_data.begin();
            while (t--) {
                while ((val & mask) == 0 && mask) {
                    mask >>= 1;
                    ++dest;
                };
                *dest++ = *src++;
                mask >>= 1;
            };
            pr_debug("after replace : ", data.discretionary_data, "\n");
        }

        // S13.19
        // Copy nUN' into the least significant digit of the 'Discretionary Data' in Track 2 Data
        data.discretionary_data[data.discretionary_data.size() - 1] = _nUN + '0';
        pr_debug("final dd : ", data.discretionary_data, "\n");

        auto track2_data = TAG_TRACK2_DATA_9F6B::serialize(data);
        pr_debug("final track 2 ", track2_data, "\n");
        kernel_db.update(tlv_obj(TRACK2_DATA_9F6B.id, track2_data));
    }

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s13_wait_for_ccc_response_1 = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug("enter s13_wait_for_ccc_response_1\n");
        switch (sig) {
        case SIGNAL::RA: {
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                outcome_builder builder{kernel_db};
                builder.error(sw1, sw2);
                return s13_invalid_response(builder);
            } else {
                // S13.11
                if (!kernel_db.parse_store_card_response(apdu)) {
                    // S13.13
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::PARSING_ERROR);
                    return s13_invalid_response(builder);
                } else {
                    outcome_builder builder{kernel_db};
                    builder.ui(ui_message_id::NO_MESSAGE, ui_status_id::CARD_READ_OK).hold().msg();
                }

                // S13.14.1
                if (!kernel_db.has_non_empty_tag(ATC_9F36)) {
                    // S13.14.4
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::CARD_DATA_MISSING);
                    return s13_invalid_response(builder);
                }

                // S13.14.2
                if (!kernel_db.has_non_empty_tag(CVC3_TRACK2_9F61)) {
                    // S13.14.3
                    if (kernel_db.has_non_empty_tag(POS_CARDHOLDER_INTERACTION_INFO_DF4B)) {
                        // S13.41
                        bool second_tap = false;
                        auto& pcii = kernel_db[POS_CARDHOLDER_INTERACTION_INFO_DF4B];
                        if ((pcii[1] & 0x03) || (pcii[2] & 0x0F))
                            second_tap = true;

                        outcome_builder builder{kernel_db};

                        if (second_tap) {
                            // S13.44
                            builder.status(OUTCOME_TYPE::END_APPLICATION);
                            auto& table = kernel_db[PHONE_MESSAGE_TABLE_DF8131];
                            for (auto p = table.data(); p < table.data() + table.size(); p += 8) {
                                auto& pcii = kernel_db[POS_CARDHOLDER_INTERACTION_INFO_DF4B];
                                if ((p[0] & pcii[0]) == p[3] &&
                                    (p[1] & pcii[1]) == p[4] &&
                                    (p[2] & pcii[2]) == p[5]) {
                                    builder.hold(kernel_db[MESSAGE_HOLD_TIME_DF812D])
                                        .ui(static_cast<ui_message_id>(p[6]), static_cast<ui_status_id>(p[7]))
                                        .msg();
                                    break;
                                }
                            };
                            // S13.44.1
                            // TODO
                            // wait for (2^failed_ms_cntr * 300) ms

                            // S13.44.2
                            if (++failed_ms_cntr > 5)
                                failed_ms_cntr = 5;

                            // S13.45
                            emvl2->generate_outcome(builder.hold()
                                                        .ui(ui_status_id::PRESENT_CARD)
                                                        .ui_on_restart()
                                                        .status(OUTCOME_TYPE::END_APPLICATION)
                                                        .start(RESTART_POINT::B)
                                                        .create_ms_dr<KERNEL2_NS>()
                                                        .create_ms_dd<KERNEL2_NS>()
                                                        .post());
                            return KSTATUS::EXIT_KERNEL;
                        } else {
                            // S13.42.1
                            // TODO
                            // wait for (2^failed_ms_cntr * 300) ms

                            // S13.42.2
                            if (++failed_ms_cntr > 5)
                                failed_ms_cntr = 5;

                            // S13.43
                            emvl2->generate_outcome(builder.hold(kernel_db[MESSAGE_HOLD_TIME_DF812D])
                                                        .ui(ui_message_id::NOT_AUTHORIZED, ui_status_id::NOT_READY)
                                                        .status(OUTCOME_TYPE::DECLINED)
                                                        .ui_on_outcome()
                                                        .create_ms_dd<KERNEL2_NS>()
                                                        .create_ms_dr<KERNEL2_NS>()
                                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                        .pack(DATA_RECORD_FF8105)
                                                        .pack(DISCRETIONARY_DATA_FF8106)
                                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                        .post());
                            return KSTATUS::EXIT_KERNEL;
                        }
                    } else {
                        // S13.14.4
                        outcome_builder builder{kernel_db};
                        builder.error(L2_ERROR::CARD_DATA_MISSING);
                        return s13_invalid_response(builder);
                    }
                } else {
                    // S13.14.5
                    uint8_t nUN = get_num_of_bit_one(kernel_db[KERNEL2::PUNATC_TRACK2_9F66]) -
                                  kernel_db[NATC_TRACK2_9F67][0];
                    pr_debug("PUNATC_TRACK2_9F66 ", kernel_db[KERNEL2::PUNATC_TRACK2_9F66], "\n");
                    pr_debug("NATC_TRACK2_9F67 ", kernel_db[NATC_TRACK2_9F67], "\n");
                    pr_debug("nUN ", nUN, "\n");
                    uint8_t _nUN;
                    if (!kernel_db.has_non_empty_tag(POS_CARDHOLDER_INTERACTION_INFO_DF4B) ||
                        // S13.14.6
                        !kernel_db.get_bit(POS_CARDHOLDER_INTERACTION_INFO_DF4B,
                                           TAG_POS_CARDHOLDER_INTERACTION_INFO_DF4B::od_cvm_verification_successful)) {
                        _nUN = nUN;
                        // S13.14.7
                    } else {
                        // S13.14.8
                        _nUN = (nUN + 5) % 10;
                    }
                    pr_debug("_nUN ", _nUN, "\n");

                    // S13.15
                    if (kernel_db.has_non_empty_tag(TRACK1_DATA_56) &&
                        (!kernel_db.has_tag(CVC3_TRACK1_9F60) ||
                         kernel_db.has_empty_tag(CVC3_TRACK1_9F60))) {
                        // S13.16
                        outcome_builder builder{kernel_db};
                        builder.error(L2_ERROR::CARD_DATA_MISSING);
                        return s13_invalid_response(builder);
                    }

                    // S13.17
                    failed_ms_cntr = 0;

                    // S13.18
                    ms_patch_track2_data(nUN, _nUN);
                    // S13.20
                    if (kernel_db.has_non_empty_tag(TRACK1_DATA_56)) {
                        ms_patch_track1_data(nUN, _nUN);
                    };

                    // S13. 24
                    auto value = kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
                    auto limit = tag_n::to_numeric_value(kernel_db[READER_CVM_REQUIRED_LIMIT_DF8126]);
                    if (value > limit) {
                        // S13.26
                        auto cvm = kernel_db(MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E);
                        outcome_builder builder{kernel_db};
                        emvl2->generate_outcome(builder.status(OUTCOME_TYPE::ONLINE_REQUEST)
                                                    .cvm(cvm)
                                                    .receipt(true)
                                                    .create_ms_dr<KERNEL2_NS>()
                                                    .create_ms_dd<KERNEL2_NS>()
                                                    .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                    .pack(DATA_RECORD_FF8105)
                                                    .pack(DISCRETIONARY_DATA_FF8106)
                                                    .post());

                    } else {
                        // S13.25
                        auto cvm = kernel_db(MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C);
                        outcome_builder builder{kernel_db};
                        emvl2->generate_outcome(builder.status(OUTCOME_TYPE::ONLINE_REQUEST)
                                                    .cvm(cvm)
                                                    .receipt(cvm == OUTCOME_CVM::SIGNATURE)
                                                    .create_ms_dr<KERNEL2_NS>()
                                                    .create_ms_dd<KERNEL2_NS>()
                                                    .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                    .pack(DATA_RECORD_FF8105)
                                                    .pack(DISCRETIONARY_DATA_FF8106)
                                                    .post());
                    }
                    return KSTATUS::EXIT_KERNEL;
                }
            };

            break;
        };
        case SIGNAL::STOP: // S13.7
        case SIGNAL::DET:  // S13.8
            break;
        case SIGNAL::L1RSP: { // S13.1
            // S13.2
            // TODO
            // wait for (2^failed_ms_cntr * 300) ms
            // S13.3
            if (++failed_ms_cntr > 5)
                failed_ms_cntr = 5;

            // S13.4, 5
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .ui_on_restart()
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_ms_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s14_wait_for_ccc_response_2 = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug("enter s14_wait_for_ccc_response_2\n");
        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s4_wait_for_emv_read_record = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        switch (sig) {
        case SIGNAL::RA: {
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                pr_debug("read record response failure\n");
                // S4.10.1, 2
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                            .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                            .ui_on_outcome()
                                            .error(sw1, sw2)
                                            .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                            .create_emv_dd<KERNEL2_NS>()
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            } else {
                // S4.11 ~ 14
                uint8_t sfi = 0;
                bool signed_record = false;
                kernel_db.get_record_and_move_to_next(signed_record, sfi);
                NEXT_CMD next_cmd = NEXT_CMD::NONE;

                // s4.15
                if (kernel_db.tags_to_read_yet.begin() != kernel_db.tags_to_read_yet.end()) {
                    auto active_tag = kernel_db.tags_to_read_yet.begin();
                    uint8_t p1 = static_cast<uint8_t>((*active_tag >> 8) & 0xFF);
                    uint8_t p2 = static_cast<uint8_t>((*active_tag) & 0xFF);
                    emvl2->send_apdu(apdu_builder::build(COMMANDS::GET_DATA).p1(p1).p2(p2).le(0).to_bytes());
                    next_cmd = NEXT_CMD::GET_DATA;
                } else if (!kernel_db.is_afl_empty()) {
                    kernel_db.read_next_record(emvl2);
                    next_cmd = NEXT_CMD::READ_RECORD;
                }

                bool parse_result = kernel_db.parse_record(apdu, signed_record, sfi);
                if (!parse_result) {
                    if (next_cmd != NEXT_CMD::NONE) {
                        enter_state(&s4_terminate_on_next_ra);
                        break;
                    } else {
                        // S4.27
                        outcome_builder builder{kernel_db};
                        emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                                    .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                                    .ui_on_outcome()
                                                    .error(L2_ERROR::PARSING_ERROR)
                                                    .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                                    .create_emv_dd<KERNEL2_NS>()
                                                    .pack(OUTCOME_PARAMETER_SET_DF8129)
                                                    .pack(DISCRETIONARY_DATA_FF8106)
                                                    .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                                    .post());
                        return KSTATUS::EXIT_KERNEL;
                    }
                }

                if (kernel_db.has_tag(CDOL1_8C)) {
                    check_dol_if_needed(CDOL1_8C);
                };

                if (kernel_db.has_tag(DSDOL_9F5B) &&
                    kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read) &&
                    !(kernel_db.has_non_empty_tag(DS_SLOT_MANAGEMENT_CONTROL_9F6F) &&
                      kernel_db.get_bit(DS_SLOT_MANAGEMENT_CONTROL_9F6F, TAG_DS_SLOT_MANAGEMENT_CONTROL_9F6F::locked_slot))) {
                    check_dol_if_needed(DSDOL_9F5B);
                };
                return s456(next_cmd);
            };

            break;
        };
        case SIGNAL::STOP: {
            // S4.8
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::DET:
            kernel_db.update_with_det_data(*param);
            break;
        case SIGNAL::L1RSP: {
            // S4.6
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .ui_on_outcome()
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    void check_dol_if_needed(const tag_info& tag) {
        auto dol = kernel_db[tag];
        std::vector<dol_elem> elems{};
        tlv_parse_dol(dol.begin(), dol.end(), elems);
        auto& data_needed = kernel_db[DATA_NEEDED_DF8106];
        for (auto& e : elems) {
            if (kernel_db.has_empty_tag(e.tag)) {
                auto info = find_tag_info(e.tag);
                pr_debug(to_hex(e.tag), " [", info != nullptr ? std::string(info->desc) : "Unknown", "] missing from ", std::string(tag.desc), "\n");
                auto p = tag_in_bytes(e.tag);
                std::copy(p.begin(), p.end(), std::back_inserter(data_needed));
            }
        };
    };

    KSTATUS proceed_to_write() {
        //S456.12
        if (!kernel_db.has_non_empty_tag(AMOUNT_AUTHORISED_9F02)) {
            // S456.13
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::AMOUNT_NOT_PRESENT)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());

            return KSTATUS::EXIT_KERNEL;
        };

        // S456.14
        auto value = kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
        auto contactless_limit = tag_n::to_numeric_value(kernel_db.contactless_transaction_limit);
        if (value > contactless_limit) {
            // S456.15
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::SELECT_NEXT)
                                        .field_off()
                                        .start(RESTART_POINT::C)
                                        .error(L2_ERROR::MAX_LIMIT_EXCEEDED)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());

            return KSTATUS::EXIT_KERNEL;
        };

        // S456.16
        if (!(kernel_db.has_non_empty_tag(APPLICATION_EXPIRE_DATE_5F24) &&
              kernel_db.has_non_empty_tag(PAN_5A) &&
              kernel_db.has_non_empty_tag(CDOL1_8C))) {
            // S456.17
            pr_error("failing S456.17, missing mandaotry tags, 8C || 5A || 5F24 \n");
            kernel_db.print();
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                        .ui_on_outcome()
                                        .error(L2_ERROR::CARD_DATA_MISSING)
                                        .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }

        // S456.18
        if (kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
            std::string pan_seq{};
            if (kernel_db.has_tag(PAN_SEQ_5F34)) {
                pan_seq = vector2hex(kernel_db[PAN_SEQ_5F34]);
            } else {
                pan_seq = std::string("00");
            }
            auto pan = PAN_5A.to_string(kernel_db[PAN_5A]);
            pan = pan + pan_seq;
            auto ds_id = DS_ID_9F5E.to_string(kernel_db[DS_ID_9F5E]);
            if (ds_id != pan) {
                // S456.20.1, 2
                pr_debug("ds id does not match pan+seq\n");
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                            .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                            .ui_on_outcome()
                                            .error(L2_ERROR::CARD_DATA_ERROR)
                                            .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                            .create_emv_dd<KERNEL2_NS>()
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            }
        }

        // S456.21
        drain_tags_to_read_yet(true);
        if (!kernel_db.has_empty_tag(DATA_TO_SEND_FF8104.id)) {
            // FIXME only data_to_send handled on spec
            send_dek();
        }

        // S456.25
        auto tvr = kernel_db[TVR_95];
        if (kernel_db.oda_status.cda) {
            if (!(kernel_db.has_non_empty_tag(CA_PUBLIC_KEY_INDEX_8F) &&
                  kernel_db.has_non_empty_tag(ISSUER_PUB_KEY_CERT_90) &&
                  kernel_db.has_non_empty_tag(ISSUER_PUB_KEY_EXP_9F32) &&
                  kernel_db.has_non_empty_tag(ICC_PUB_KEY_CERT_9F46) &&
                  kernel_db.has_non_empty_tag(ISSUER_PUB_KEY_EXP_9F32) &&
                  kernel_db.has_non_empty_tag(SDA_TAG_LIST_9F4A))) {
                v_set_bit(tvr, TAG_TVR_95::icc_data_missing);
                v_set_bit(tvr, TAG_TVR_95::cda_failed);
            }
            if (emvl2->find_ca_key(get_rid(), kernel_db(CA_PUBLIC_KEY_INDEX_8F)) == nullptr) {
                pr_error("fail to find ca key\n");
                v_set_bit(tvr, TAG_TVR_95::cda_failed);
            }

            if (!(kernel_db.has_non_empty_tag(SDA_TAG_LIST_9F4A.id) &&
                  kernel_db[SDA_TAG_LIST_9F4A][0] == 0x82)) {
                // S456.27.1, 2
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                            .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                            .ui_on_outcome()
                                            .error(L2_ERROR::CARD_DATA_ERROR)
                                            .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                            .create_emv_dd<KERNEL2_NS>()
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            }
        }

        value = kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
        auto cvm_limit = kernel_db.get_numeric_value(READER_CVM_REQUIRED_LIMIT_DF8126);
        pr_debug("amount ", (int)value, " cvm required limit ", (int)cvm_limit, "\n");
        auto& cap = kernel_db[TERMINAL_CAPABILITIES_9F33];
        // S456.30
        if (value > cvm_limit) {
            kernel_db.set_bit(OUTCOME_PARAMETER_SET_DF8129, TAG_OUTCOME_PARAMETER_SET_DF8129::receipt_required);
            cap[1] = kernel_db[CVM_CAPABILITY_CVM_REQUIRED_DF8118][0];
        } else {
            cap[1] = kernel_db[CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119][0];
        }

        // S456.34
        return pre_gen_ac_balance_reading();
    }

    KSTATUS CONTINUE_AFTER_BR1() {
        // S456.35
        process_restriction();

        // S456.36
        process_cvm_selection();

        auto value = kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
        auto floor_limit = kernel_db.get_numeric_value(READER_CONTACTLESS_FLOOR_LIMIT_DF8123);
        pr_debug("floor limit ", (int)floor_limit, "\n");
        if (value > floor_limit) {
            kernel_db.set_bit(TVR_95, TAG_TVR_95::transaction_exceeds_floor_limit);
        }

        // S456.39
        terminal_action_analysis();

        // S456.42
        if (!kernel_db.tags_to_write_yet_before_gen_ac.empty()) {
            // S456.50
            auto tlv = kernel_db.tags_to_write_yet_before_gen_ac.get_and_remove_from_list();
            uint32_t tag = tlv.first;
            uint8_t p1 = static_cast<uint8_t>((tag >> 8) & 0xFF);
            uint8_t p2 = static_cast<uint8_t>((tag)&0xFF);
            emvl2->send_apdu(apdu_builder::build(COMMANDS::PUT_DATA).data(tlv.second).p1(p1).p2(p2).to_bytes());
            enter_state(&s12_waiting_for_put_data_response_before_generate_ac);
            return KSTATUS::DEFAULT;
        }

        // S456.43
        if (kernel_db.has_non_empty_tag(DRDOL_9F51) &&
            kernel_db[MAX_NUMBER_OF_TORN_RECORDS_DF811D][0] != 0) {
            auto& torn = emvl2->torn_transactions;
            auto p = torn.find(kernel_db);
            if (p != torn.cend()) {
                pr_debug("find torn transaction\n");
                auto drdol = kernel_db[DRDOL_9F51];
                std::vector<uint8_t> drdol_related_data;
                std::vector<uint8_t> missing_tags;
                build_dol(DRDOL_9F51.id, drdol, *p, drdol_related_data, missing_tags);

                emvl2->send_apdu(apdu_builder::build(COMMANDS::RECOVER_AC).le(0).data(drdol_related_data).to_bytes());
                enter_state(&s10_waiting_for_recover_ac_response);
                return KSTATUS::DEFAULT;
            };
        }

        auto ret = generate_ac();
        if (ret != KSTATUS::DEFAULT)
            return ret;

        enter_state(&s9_waiting_for_generate_ac_response_1);

        return KSTATUS::DEFAULT;
    }

    KSTATUS generate_ac_no_ids() {
        auto ref = kernel_db[REFERENCE_CONTROL_PARAMETER_DF8114];
        auto cdol1 = kernel_db[CDOL1_8C];
        std::vector<uint8_t> cdol1_related_data{};
        std::vector<uint8_t> missing_tags{};
        build_dol(CDOL1_8C.id, cdol1, kernel_db, cdol1_related_data, missing_tags);

        kernel_db.insert(tlv_obj{CDOL1_RELATED_DATA_DF8107.id, cdol1_related_data});

        emvl2->send_apdu(apdu_builder::build(COMMANDS::GENERATE_AC).le(0).p1(ref[0]).p2(0).data(cdol1_related_data).to_bytes());
        return KSTATUS::DEFAULT;
    };

    KSTATUS generate_ac_ids_write() {
        if (kernel_db.has_tag(DS_DIGEST_H_DF61) &&
            kernel_db.has_tag(DS_INPUT_TERM_DF8109)) {
            auto& ds_digest_h = kernel_db[DS_DIGEST_H_DF61];
            // GAC.42
            auto& v = kernel_db[KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D];
            if (KERNEL2::TAG_APPLICATION_CAPABILITIES_INFO_9F5D::get_ds_version(v) == 1) {
                // GAC.43
                ds_digest_h = OWHF2();
            } else {
                // GAC.44
                ds_digest_h = OWHF2AES();
            }
        }

        // GAC.45
        kernel_db.initialize(REFERENCE_CONTROL_PARAMETER_DF8114);
        auto& ref = kernel_db[REFERENCE_CONTROL_PARAMETER_DF8114];
        TAG_REFERENCE_CONTROL_PARAMETER_DF8114::set_ac_type(ref, kernel_db.ac_type);
        v_set_bit(ref, TAG_REFERENCE_CONTROL_PARAMETER_DF8114::cda_signature_requested);

        auto cdol1 = kernel_db[CDOL1_8C];
        std::vector<uint8_t> cdol1_related_data;
        std::vector<uint8_t> missing_tags;
        build_dol(CDOL1_8C.id, cdol1, kernel_db, cdol1_related_data, missing_tags);
        kernel_db.insert(tlv_obj{CDOL1_RELATED_DATA_DF8107.id, cdol1_related_data});

        auto dsdol = kernel_db[DSDOL_9F5B];
        std::vector<uint8_t> dsdol_related_data;
        build_dol(DSDOL_9F5B.id, dsdol, kernel_db, dsdol_related_data, missing_tags);

        std::copy(dsdol_related_data.begin(), dsdol_related_data.end(),
                  back_inserter(cdol1_related_data));

        emvl2->send_apdu(apdu_builder::build(COMMANDS::GENERATE_AC).le(0).p1(ref[0]).p2(0).data(cdol1_related_data).to_bytes());

        return KSTATUS::DEFAULT;
    };

    // section 7.6
    KSTATUS generate_ac() {
        pr_debug("generating AC ..\n");
        pr_debug("TVR ", kernel_db[TVR_95], "\n");
        dump(TVR_95, kernel_db[TVR_95]);
        if (kernel_db.has_non_empty_tag(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D)) {
            pr_debug("application capability info\n");
            dump(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D, kernel_db[KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D]);
        }
        pr_debug("terminal capability ", kernel_db[TERMINAL_CAPABILITIES_9F33], "\n");
        dump(TERMINAL_CAPABILITIES_9F33, kernel_db[TERMINAL_CAPABILITIES_9F33]);

        auto& tvr = kernel_db[TVR_95];
        auto& aip = kernel_db[AIP_82];
        auto& kcfg = kernel_db[KERNEL_CONFIGURATION_DF811B];
        tlv_obj ref{REFERENCE_CONTROL_PARAMETER_DF8114.id, std::vector<uint8_t>(1)};

        // GAC.1
        if (!kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
            goto No_IDS_B;
        };

        // GAC.2
        if (v_get_bit(tvr, TAG_TVR_95::cda_failed)) {
            goto CDA_Failed;
        };

        // GAC3, 4
        if (!kernel_db.has_non_empty_tag(DS_ODS_INFO_DF62) ||
            !kernel_db.has_non_empty_tag(DSDOL_9F5B)) {
            goto IDS_Read_Only;
        }

        goto GAC5;

    No_IDS_B:
        // GAC.20
        pr_debug("check cda status ", (int)kernel_db.oda_status.cda, " cda failed bit ", (int)!!v_get_bit(tvr, TAG_TVR_95::cda_failed), "\n");

        if (!kernel_db.oda_status.cda ||
            v_get_bit(tvr, TAG_TVR_95::cda_failed)) {
        CDA_Failed:
            // GAC.22
            if (v_get_bit(aip, TAG_AIP_82::on_device_cardholder_verification_supported) &&
                v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::on_device_verification_supported)) {
                // GAC.23
                kernel_db.ac_type = AC_TYPE::AAC;
            }
        } else {
            // GAC.24
            if (kernel_db.ac_type != AC_TYPE::AAC ||
                // GAC.25
                (kernel_db.has_non_empty_tag(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D) &&
                 kernel_db.get_bit(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D,
                                   KERNEL2::TAG_APPLICATION_CAPABILITIES_INFO_9F5D::cda_supported_over_tc_arqc_aac))) {
            IDS_Read_Only:
                // GAC.27
                v_set_bit(ref.second, TAG_REFERENCE_CONTROL_PARAMETER_DF8114::cda_signature_requested);
            }
        }

        // GAC.26
        TAG_REFERENCE_CONTROL_PARAMETER_DF8114::set_ac_type(ref.second, kernel_db.ac_type);
        kernel_db.insert(std::move(ref));

        // GAC.29
        return generate_ac_no_ids();

    // GAC5
    GAC5:
        if (!(kernel_db.has_non_empty_tag(DS_AC_TYPE_DF8108) &&
              kernel_db.has_non_empty_tag(DS_ODS_INFO_FOR_READER_DF810A))) {
            // GAC 6, 12, 13
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                        .ui_on_outcome()
                                        .error(L2_ERROR::IDS_DATA_ERROR)
                                        .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());

            return KSTATUS::EXIT_KERNEL;
        };

        // GAC7
        AC_TYPE ds_ac_type = kernel_db(DS_AC_TYPE_DF8108);
        if (ds_ac_type == AC_TYPE::AAC ||
            kernel_db.ac_type == ds_ac_type ||
            ((ds_ac_type == AC_TYPE::ARQC && kernel_db.ac_type == AC_TYPE::TC))) {
            // GAC8
            kernel_db.ac_type = ds_ac_type;
            return generate_ac_ids_write();
        };

        // GAC.9
        auto& ds_ods_info = kernel_db[DS_ODS_INFO_FOR_READER_DF810A];
        if ((kernel_db.ac_type == AC_TYPE::AAC && v_get_bit(ds_ods_info, TAG_DS_ODS_INFO_FOR_READER_DF810A::usable_for_aac)) ||
            (kernel_db.ac_type == AC_TYPE::ARQC && v_get_bit(ds_ods_info, TAG_DS_ODS_INFO_FOR_READER_DF810A::usable_for_arqc))) {
            return generate_ac_ids_write();
        }

        // GAC.10
        if (!v_get_bit(ds_ods_info, TAG_DS_ODS_INFO_FOR_READER_DF810A::stop_if_no_ds_ods_term)) {
            goto IDS_Read_Only;
        };

        // GAC.12, 13
        outcome_builder builder{kernel_db};
        emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                    .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                    .ui_on_outcome()
                                    .error(L2_ERROR::IDS_NO_MATCHING_AC)
                                    .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                    .create_emv_dd<KERNEL2_NS>()
                                    .pack(OUTCOME_PARAMETER_SET_DF8129)
                                    .pack(DISCRETIONARY_DATA_FF8106)
                                    .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                    .post());

        return KSTATUS::EXIT_KERNEL;
    }

    // TODO
    std::vector<uint8_t> OWHF2() {
        pr_debug("OWHF2 NOT IMPLEMENTED YET\n");
        return std::vector<uint8_t>{};
    }

    // TODO
    std::vector<uint8_t> OWHF2AES() {
        pr_debug("OWHF2AES NOT IMPLEMENTED YET\n");
        return std::vector<uint8_t>{};
    };

    inline int and_vect(const std::vector<uint8_t>& v1,
                        const std::vector<uint8_t>& v2) {
        for (unsigned i = 0; i != v1.size(); i++) {
            if (v1[i] & v2[i]) {
                return 1;
            }
        }

        return 0;
    }

    void terminal_action_analysis(){
        auto& tvr = kernel_db[TVR_95];

        if (and_vect(kernel_db[TAC_DENIAL_DF8121],
                     tvr)) {
            kernel_db.ac_type = AC_TYPE::AAC;
            return;
        }

        if (kernel_db.has_non_empty_tag(IAC_DENIAL_9F0E) &&
            and_vect(kernel_db[IAC_DENIAL_9F0E],
                     tvr)) {
            kernel_db.ac_type = AC_TYPE::AAC;
            return;
        }

        auto terminal_type = kernel_db[TERMINAL_TYPE_9F35][0];
        // TAA 4.1
        if (terminal_type == 0x11 || terminal_type == 0x21 ||
            terminal_type == 0x14 || terminal_type == 0x24 || terminal_type == 0x34) {
            // TAA 4.2
            kernel_db.ac_type = AC_TYPE::ARQC;
            return;
        }

        // TAA 6
        if (!(terminal_type == 0x23 || terminal_type == 0x26 ||
              terminal_type == 0x36 || terminal_type == 0x13 ||
              terminal_type == 0x16)) {
            if (kernel_db.has_non_empty_tag(IAC_ONLINE_9F0F)) { // TAA 7
                if (!and_vect(kernel_db[IAC_ONLINE_9F0F], tvr) &&
                    !and_vect(kernel_db[TAC_ONLINE_DF8122], tvr)) { // TAA 10
                    // TAA 12
                    kernel_db.ac_type = AC_TYPE::TC;
                }
            } else { // TAA 8
                auto p = std::find_if(tvr.begin(), tvr.end(), [](auto b) { return b != 0; });
                if (p == tvr.end()) { // TAA 9
                    kernel_db.ac_type = AC_TYPE::TC;
                    return;
                }
            }

            kernel_db.ac_type = AC_TYPE::ARQC;
            return;
        }

        // TAA 13
        if (kernel_db.has_non_empty_tag(IAC_DEFAULT_9F0D)) {
            // TAA 16
            if (!and_vect(kernel_db[TAC_DEFAULT_DF8120], tvr) &&
                !and_vect(kernel_db[IAC_DEFAULT_9F0D], tvr)) {
                // TAA 18
                kernel_db.ac_type = AC_TYPE::TC;
                return;
            }
        } else {
            // TAA 14
            auto p = std::find_if(tvr.begin(), tvr.end(), [](auto b) { return b != 0; });
            if (p == tvr.end()) { // TAA 15
                kernel_db.ac_type = AC_TYPE::TC;
                return;
            }
        }

        // TAA 17
        kernel_db.ac_type = AC_TYPE::AAC;
    };

    // TODO  sectoin 7.5
    void process_cvm_selection(){
        auto& aip = kernel_db[AIP_82];
        auto& kcfg = kernel_db[KERNEL_CONFIGURATION_DF811B];
        auto& cvm = kernel_db[CVM_RESULT_9F34];
        auto& outcome = kernel_db[OUTCOME_PARAMETER_SET_DF8129];
        // CVM.1
        if (v_get_bit(aip, TAG_AIP_82::on_device_cardholder_verification_supported) &&
            v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::on_device_verification_supported)) {
            // CVM2
            auto amount = kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
            auto limit = kernel_db.get_numeric_value(READER_CVM_REQUIRED_LIMIT_DF8126);
            auto& outcome = kernel_db[OUTCOME_PARAMETER_SET_DF8129];
            if (amount > limit) {
                // CVM4
                TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome, OUTCOME_CVM::CONF_CODE_VERIFIED);
                TAG_CVM_RESULT_9F34::set_performed(cvm, CVM_CODE::PLAINTEXT_PIN_VERIFICATION_PERFORMED_BY_ICC);
                TAG_CVM_RESULT_9F34::set_condition(cvm, CVM_CONDITION::ALWAYS);
                TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::SUCCESSFUL);

            } else {
                // CVM3
                TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                          OUTCOME_CVM::NO_CVM);
                TAG_CVM_RESULT_9F34::set_performed(cvm, CVM_CODE::NO_CVM_PERFORMED);
                TAG_CVM_RESULT_9F34::set_condition(cvm, CVM_CONDITION::ALWAYS);
                TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::SUCCESSFUL);
            }
	    return;
        }
        // CVM5
        if (!v_get_bit(aip, TAG_AIP_82::cardholder_verification_supported)) {
            // CVM6
            TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                      OUTCOME_CVM::NO_CVM);
            TAG_CVM_RESULT_9F34::set_performed(cvm, CVM_CODE::NO_CVM_PERFORMED);
            TAG_CVM_RESULT_9F34::set_condition(cvm, CVM_CONDITION::ALWAYS);
            TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::UNKNOWN);
            return;
        };

        // CVM7
        if (!kernel_db.has_tag(CVM_LIST_8E) ||
            kernel_db.has_empty_tag(CVM_LIST_8E)) {
            // CVM8
            TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                      OUTCOME_CVM::NO_CVM);
            TAG_CVM_RESULT_9F34::set_performed(cvm, CVM_CODE::NO_CVM_PERFORMED);
            TAG_CVM_RESULT_9F34::set_condition(cvm, CVM_CONDITION::ALWAYS);
            TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::UNKNOWN);
            kernel_db.set_bit(TVR_95, TAG_TVR_95::icc_data_missing);
            return;
        }

        // CVM9
        auto& cvm_list = kernel_db[CVM_LIST_8E];
        pr_debug("process cvm list ", cvm_list, "\n");

        // EVM Book 3, 10.5
        // if the CVM List is not present in the ICC, the terminal shall terminate
        // cardholder verification without setting the ‘Cardholder verification was
        // performed’ bit in the TSI.
        // Note: A CVM List with no Cardholder Verification Rules is considered to be the same as
        // a CVM List not being present.
        if (cvm_list.size() <= 8)
            return;
        auto& tvr = kernel_db[TVR_95];
        auto x = cvm_list.cbegin();
        auto y = cvm_list.cbegin() + 4;

        auto cvr = cvm_list.cbegin() + 8;

        // TODO  Book 3, 10.5
        // If the terminal encounters formatting errors in the CVM List such as a list with
        // an odd number of bytes (that is, with an incomplete CVM Rule), the terminal
        // shall terminate the transaction as specified in Book 3 section 7.5.

        while (cvr + 1 < cvm_list.end()) {
            auto cvm_code = cvr[0] & 0x3F;
            auto cvm_condition = cvr[1];
            pr_debug("handling CVR ", std::vector<uint8_t>{cvr, cvr + 2}, "\n");

            if (cvm_condition <= 9 &&                                     // CVM10
                cvm_conditoin_data_present(cvm_condition) &&              // CVM11
                cvm_condition_satisfied(x, y, cvm_code, cvm_condition)) { // CVM12
                if (is_cvm_recognized(cvm_code)) {                        // CVM15
                    if (terminal_support_cvm(cvm_code) &&
                        cvm_code != static_cast<uint8_t>(CVM_CODE::FAILED_CVM_PROCESSING)) { // CVM17
                        // TODO
                        // CVM.18
                        if (cvm_code == static_cast<uint8_t>(CVM_CODE::ENCIPHERED_PIN_VERIFIED_ONLINE)) {
                            TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                                      OUTCOME_CVM::ONLINE_PIN);
                            TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::UNKNOWN);
                            v_set_bit(tvr, TAG_TVR_95::online_pin_entered);
                        } else {
                            if (cvm_code == static_cast<uint8_t>(CVM_CODE::SIGNATURE)) {
                                TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                                          OUTCOME_CVM::SIGNATURE);
                                TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::UNKNOWN);
                                v_set_bit(outcome, TAG_OUTCOME_PARAMETER_SET_DF8129::receipt_required);
                            } else {
                                if (cvm_code == static_cast<uint8_t>(CVM_CODE::NO_CVM_REQUIRED)) {
                                    TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                                              OUTCOME_CVM::NO_CVM);
                                    TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::SUCCESSFUL);
                                } else {
                                    pr_error("we probably should never reach here\n");
                                    TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                                              OUTCOME_CVM::NA);
                                    TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::SUCCESSFUL);
                                }
                            }
                        }
                        TAG_CVM_RESULT_9F34::set_performed(cvm, static_cast<CVM_CODE>(cvm_code));
                        TAG_CVM_RESULT_9F34::set_condition(cvm, static_cast<CVM_CONDITION>(cvm_condition));
                        return;
                    } else {
                        pr_debug("CVM is not supported\n");
                    }
                } else {
                    // CVM.16
                    pr_debug("CVM is not recognized\n");
                    kernel_db.set_bit(TVR_95, TAG_TVR_95::unrecognized_cvm);
                }

                // CVM19
                if (cvr[8] & 0x40) { // bit 7 of CVM code set for succeeding rule
                    cvr += 2;
                    if (cvr < cvm_list.end()) {
                        continue;
                    }
                }

                // CVM.22
                TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                          OUTCOME_CVM::NO_CVM);
                v_set_bit(tvr, TAG_TVR_95::cardholder_verification_not_successful);

                if (cvm_code == static_cast<uint8_t>(CVM_CODE::FAILED_CVM_PROCESSING)) {
                    // CVM24
                    TAG_CVM_RESULT_9F34::set_performed(cvm, static_cast<CVM_CODE>(cvm_code));
                    TAG_CVM_RESULT_9F34::set_condition(cvm, static_cast<CVM_CONDITION>(cvm_condition));
                    TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::FAILED);

                } else {
                    // CVM25
                    TAG_CVM_RESULT_9F34::set_performed(cvm, CVM_CODE::NO_CVM_PERFORMED);
                    TAG_CVM_RESULT_9F34::set_condition(cvm, CVM_CONDITION::ALWAYS);
                    TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::FAILED);
                }

                return;
            } else {
                cvr += 2;
                // CVM13
                if (cvr < cvm_list.end()) {
                    continue;
                } else {
                    // CVM14
                    TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome,
                                                              OUTCOME_CVM::NO_CVM);
                    v_set_bit(tvr, TAG_TVR_95::cardholder_verification_not_successful);
                    TAG_CVM_RESULT_9F34::set_performed(cvm, CVM_CODE::NO_CVM_PERFORMED);
                    TAG_CVM_RESULT_9F34::set_condition(cvm, CVM_CONDITION::ALWAYS);
                    TAG_CVM_RESULT_9F34::set_result(cvm, CVM_RESULT::FAILED);
                    return;
                }
            }
        };
    };

    bool cvm_conditoin_data_present(uint8_t condition) {
        switch (static_cast<CVM_CONDITION>(condition)) {
        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_UNDER_X:
        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_OVER_X:
        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_UNDER_Y:
        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_OVER_Y:
            return kernel_db.has_tag(APPLICATION_CURRENCY_CODE_9F42);
        default:
            break;
        }
        return true;
    };

    inline uint32_t to_uint32(std::vector<uint8_t>::const_iterator v) {
        return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
    }

    bool cvm_condition_satisfied(std::vector<uint8_t>::const_iterator x, std::vector<uint8_t>::const_iterator y, uint8_t code, uint8_t condition) {
        switch (static_cast<CVM_CONDITION>(condition)) {
        case CVM_CONDITION::ALWAYS:
            break;
        case CVM_CONDITION::IF_UNATTENDED_CASH: {
            auto type = kernel_db(TRANSACTION_TYPE_9C);
            bool unattended = TAG_TERMINAL_TYPE_9F35::is_unattended(kernel_db[TERMINAL_TYPE_9F35]);
            bool unattended_cash = (unattended && (type == TRANSACTION_TYPE::CASH));
            return unattended_cash;
        }
        case CVM_CONDITION::IF_NOT_UNATTENDED_CASH_NOT_MANUAL_CASH_NOT_PURCHASE_WITH_CASHBACK: {
            bool unattended = TAG_TERMINAL_TYPE_9F35::is_unattended(kernel_db[TERMINAL_TYPE_9F35]);
            auto type = kernel_db(TRANSACTION_TYPE_9C);
            bool unattended_cash = (unattended && (type == TRANSACTION_TYPE::CASH));

            return !unattended_cash &&
                   type != TRANSACTION_TYPE::CASH && type != TRANSACTION_TYPE::CASH_DISBURSEMENT && type != TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK;
        }

        case CVM_CONDITION::IF_TERMINAL_SUPPORTS_THE_CVM:
            return terminal_support_cvm(code);
        case CVM_CONDITION::IF_MANUAL_CASH: {
            auto type = kernel_db(TRANSACTION_TYPE_9C);
            return type == TRANSACTION_TYPE::CASH || type == TRANSACTION_TYPE::CASH_DISBURSEMENT;
        }
        case CVM_CONDITION::IF_PURCHASE_WITH_CASHBACK:
            return kernel_db(TRANSACTION_TYPE_9C) == TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK;
        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_UNDER_X:
            return (kernel_db[APPLICATION_CURRENCY_CODE_9F42] == kernel_db[TRANSACTION_CURRENCY_CODE_5F2A] &&
                    to_uint32(x) < kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02));

        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_OVER_X:
            return (kernel_db[APPLICATION_CURRENCY_CODE_9F42] == kernel_db[TRANSACTION_CURRENCY_CODE_5F2A] &&
                    to_uint32(x) > kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02));

        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_UNDER_Y:
            return (kernel_db[APPLICATION_CURRENCY_CODE_9F42] == kernel_db[TRANSACTION_CURRENCY_CODE_5F2A] &&
                    to_uint32(y) < kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02));

        case CVM_CONDITION::IF_APPLICATION_CURRENCY_AND_OVER_Y:
            return (kernel_db[APPLICATION_CURRENCY_CODE_9F42] == kernel_db[TRANSACTION_CURRENCY_CODE_5F2A] &&
                    to_uint32(y) > kernel_db.get_numeric_value(AMOUNT_AUTHORISED_9F02));
        }

        return true;
    };

    bool is_cvm_recognized(uint8_t code) {
        switch (static_cast<CVM_CODE>(code)) {
        case CVM_CODE::FAILED_CVM_PROCESSING:
        case CVM_CODE::PLAINTEXT_PIN_VERIFICATION_PERFORMED_BY_ICC:
        case CVM_CODE::ENCIPHERED_PIN_VERIFIED_ONLINE:
        case CVM_CODE::PLAINTEXT_PIN_VERIFICATION_PERFORMED_BY_ICC_AND_SIGNATURE:
        case CVM_CODE::ENCIPHERED_PIN_VERIFICATION_PERFORMED_BY_ICC:
        case CVM_CODE::ENCIPHERED_PIN_VERIFICATION_PERFORMED_BY_ICC_AND_SIGNATURE:
        case CVM_CODE::SIGNATURE:
        case CVM_CODE::NO_CVM_REQUIRED:
            return true;
        default:
            break;
        }

        return false;
    };

    bool terminal_support_cvm(uint8_t code) {
        auto& cap = kernel_db[TERMINAL_CAPABILITIES_9F33];
        switch (static_cast<CVM_CODE>(code)) {
        case CVM_CODE::FAILED_CVM_PROCESSING:
        case CVM_CODE::NO_CVM_REQUIRED:
            return true;
        case CVM_CODE::PLAINTEXT_PIN_VERIFICATION_PERFORMED_BY_ICC:
            return v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::plaintext_pin_for_icc_verification);
        case CVM_CODE::ENCIPHERED_PIN_VERIFIED_ONLINE:
            return v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::enciphered_pin_for_online_verification);
        case CVM_CODE::PLAINTEXT_PIN_VERIFICATION_PERFORMED_BY_ICC_AND_SIGNATURE:
            return v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::plaintext_pin_for_icc_verification) && v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::signature);
        case CVM_CODE::ENCIPHERED_PIN_VERIFICATION_PERFORMED_BY_ICC:
            return v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::enciphered_pin_for_offline_verification);
        case CVM_CODE::ENCIPHERED_PIN_VERIFICATION_PERFORMED_BY_ICC_AND_SIGNATURE:
            return v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::enciphered_pin_for_offline_verification) && v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::signature);
        case CVM_CODE::SIGNATURE:
            return v_get_bit(cap, TAG_TERMINAL_CAPABILITIES_9F33::signature);
        default:
            break;
        }

        return false;
    };

    void process_restriction() {
        auto& tvr = kernel_db[TVR_95];
        if (kernel_db.has_non_empty_tag(APPLICATION_VERSION_NUMBER_CARD_9F08.id)) {
            auto& card_ver = kernel_db[APPLICATION_VERSION_NUMBER_CARD_9F08];
            auto& reader_ver = kernel_db[APPLICATION_VERSION_NUMBER_READER_9F09];
            if (card_ver != reader_ver) {
                v_set_bit(tvr, TAG_TVR_95::icc_terminal_different_app_versions);
            }
        }

        auto transact_date = kernel_db(TRANSACTION_DATE_9A);
        if (kernel_db.has_non_empty_tag(APPLICATION_EFFECTIVE_DATE_5F25)) {
            auto effective_date = kernel_db(APPLICATION_EFFECTIVE_DATE_5F25);
            if (transact_date < effective_date) {
                v_set_bit(tvr, TAG_TVR_95::application_not_effective);
            }
        }

        auto expire_date = kernel_db(APPLICATION_EXPIRE_DATE_5F24);
        if (transact_date > expire_date) {
            v_set_bit(tvr, TAG_TVR_95::expired_application);
        }

        if (!kernel_db.has_non_empty_tag(AUC_9F07)) {
            return;
        }
        auto& auc = kernel_db[AUC_9F07];
        auto terminal_type = kernel_db[TERMINAL_TYPE_9F35][0];
        auto& cap = kernel_db[ADDITIONAL_TERMINAL_CAPABILITIES_9F40];
        bool is_atm = (terminal_type == 0x14 || terminal_type == 0x15 || terminal_type == 0x16) &&
                      v_get_bit(cap, TAG_ADDITIONAL_TERMINAL_CAPABILITIES_9F40::cash);

        if ((is_atm && !v_get_bit(auc, TAG_AUC_9F07::valid_at_atm)) ||
            (!is_atm && !v_get_bit(auc, TAG_AUC_9F07::valid_other_than_atm))) {
            v_set_bit(tvr, TAG_TVR_95::requested_service_not_allowd_for_card);
            return;
        }

        if (!kernel_db.has_tag(ISSUER_COUNTRY_CODE_5F28)) {
            return;
        }
        auto icc = kernel_db[ISSUER_COUNTRY_CODE_5F28];
        auto tcc = kernel_db[TERMINAL_COUNTRY_CODE_9F1A];

        auto transact_type = kernel_db(TRANSACTION_TYPE_9C);
        if (transact_type == TRANSACTION_TYPE::CASH ||
            transact_type == TRANSACTION_TYPE::CASH_DISBURSEMENT) {
            if ((icc == tcc && !v_get_bit(auc, TAG_AUC_9F07::valid_for_domestic_cash)) ||
                (icc != tcc && !v_get_bit(auc, TAG_AUC_9F07::valid_for_international_cash))) {
                v_set_bit(tvr, TAG_TVR_95::requested_service_not_allowd_for_card);
            }
        };

        if (transact_type == TRANSACTION_TYPE::PURCHASE ||
            transact_type == TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK) {
            if ((icc == tcc && !v_get_bit(auc, TAG_AUC_9F07::valid_for_domestic_goods) && !v_get_bit(auc, TAG_AUC_9F07::valid_for_domestic_services)) ||
                (icc != tcc && !v_get_bit(auc, TAG_AUC_9F07::valid_for_international_goods) && !v_get_bit(auc, TAG_AUC_9F07::valid_for_international_services))) {
                v_set_bit(tvr, TAG_TVR_95::requested_service_not_allowd_for_card);
            }
        };

        if (kernel_db.has_tag(AMOUNT_OTHER_9F03) &&
            kernel_db.get_numeric_value(AMOUNT_OTHER_9F03) != 0) {
            if ((icc == tcc && !v_get_bit(auc, TAG_AUC_9F07::domestic_cashback_allowed)) ||
                (icc != tcc && !v_get_bit(auc, TAG_AUC_9F07::international_cashback_allowed))) {
                v_set_bit(tvr, TAG_TVR_95::requested_service_not_allowd_for_card);
            }
        }
    }

    KSTATUS handle_l1rsp_for_gac(L1_ERROR error){
        // S9.5
        if (kernel_db[MAX_NUMBER_OF_TORN_RECORDS_DF811D][0] > 0 &&
            kernel_db.has_non_empty_tag(DRDOL_9F51)) {
            // S9.11, 13
            emvl2->torn_transactions.create<KERNEL2_NS>(kernel_db);
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .ui_on_outcome()
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .error(error)
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());

            return KSTATUS::EXIT_KERNEL;

            // S9.14
        } else {
            // S9.6
            if (kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write)) {
                // S9.7, 8
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER,
                                                   ui_status_id::NOT_READY)
                                            .status(OUTCOME_TYPE::END_APPLICATION)
                                            .error(error)
                                            .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                            .create_emv_dr<KERNEL2_NS>()
                                            .create_emv_dd<KERNEL2_NS>()
                                            .ui_on_outcome()
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DATA_RECORD_FF8105)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            } else {
                // S9.9, 10
                outcome_builder builder{kernel_db};
                emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                            .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                            .hold()
                                            .start(RESTART_POINT::B)
                                            .ui_on_restart()
                                            .error(error)
                                            .msg_on_error(ui_message_id::TRY_AGAIN)
                                            .create_emv_dd<KERNEL2_NS>()
                                            .pack(OUTCOME_PARAMETER_SET_DF8129)
                                            .pack(DISCRETIONARY_DATA_FF8106)
                                            .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                            .post());

                return KSTATUS::EXIT_KERNEL;
            }
        }

        return KSTATUS::EXIT_KERNEL;
    };

    KSTATUS s11_invalid_response_2(outcome_builder& builder) {
        // S11.101
        return s910_invalid_response_2(builder);
    };

    KSTATUS s910_invalid_response_2(outcome_builder& builder) {
        // S910.61, 62
        emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                    .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                    .ui_on_outcome()
                                    .hold(kernel_db[MESSAGE_HOLD_TIME_DF812D])
                                    .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                    .create_emv_dd<KERNEL2_NS>()
                                    .ui_on_outcome()
                                    .pack(OUTCOME_PARAMETER_SET_DF8129)
                                    .pack(DISCRETIONARY_DATA_FF8106)
                                    .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                    .post());

        return KSTATUS::EXIT_KERNEL;
    };

    KSTATUS s910_invalid_response_1(outcome_builder& builder) {
        //S910.50
        builder.status(OUTCOME_TYPE::END_APPLICATION)
            .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
            .ui_on_outcome()
            .hold(kernel_db[MESSAGE_HOLD_TIME_DF812D]);

        if (kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write)) {
            // S910.52
            emvl2->generate_outcome(builder.msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .create_emv_dr<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DATA_RECORD_FF8105)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());

        } else {
            // S910.53
            emvl2->generate_outcome(builder.msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
        }

        return KSTATUS::EXIT_KERNEL;
    };

    KSTATUS s11_invalid_response_1(outcome_builder& builder) {
        // S11.90
        builder.status(OUTCOME_TYPE::END_APPLICATION)
            .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
            .ui_on_outcome()
            .hold(kernel_db[MESSAGE_HOLD_TIME_DF812D]);

        // S11.91
        auto& torn = emvl2->torn_transactions;
        auto torn_record = torn.find(kernel_db);
        if (torn_record->get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write)) {
            // S11.92
            // Torn Record = Torn Temp Record
            kernel_db.emplace(TORN_RECORD_FF8101.id, torn_record->serialize());
        };

        // S11.93
        if (kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write)) {
            //S11.94
            emvl2->generate_outcome(builder.msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .create_emv_dr<KERNEL2_NS>()
                                        .ui_on_outcome()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DATA_RECORD_FF8105)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
        } else {
            // S11.95
            emvl2->generate_outcome(builder.msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .ui_on_outcome()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
        }
        return KSTATUS::EXIT_KERNEL;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s11_waiting_for_gen_ac_response_2 = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug("enter s11_waiting_for_gen_ac_response_2\n");
        switch (sig) {
        case SIGNAL::RA: { // S11.2
                           // S11.5
            auto& torn = emvl2->torn_transactions;
            auto torn_record = torn.find(kernel_db);
            torn.remove(torn_record);

            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                // S11.7
                outcome_builder builder{kernel_db};
                builder.error(sw1, sw2);
                return s11_invalid_response_1(builder);
            } else {
                // S11.8
                bool parse_result = false;
                unsigned length = (apdu.size() >= 4) ? apdu[1] : 0;
                if (length > 0 && apdu[0] == 0x77) {
                    parse_result = kernel_db.parse_store_card_response(apdu);
                } else {
                    auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                        int length = end - begin;
                        if (tag != 0x80 ||
                            length < 11 || length > 43 ||
                            kernel_db.has_non_empty_tag(CID_9F27) ||
                            kernel_db.has_non_empty_tag(ATC_9F36) ||
                            kernel_db.has_non_empty_tag(APPLICATION_CRYPTOGRAM_9F26) ||
                            (length > 11 &&
                             kernel_db.has_non_empty_tag(ISSUER_APPLICATION_DATA_9F10))) {
                            return false;
                        } else {
                            kernel_db.save_tlv_from_card(CID_9F27.id, begin, begin + 1, false);
                            begin += 1;
                            kernel_db.save_tlv_from_card(ATC_9F36.id, begin, begin + 2, false);
                            begin += 2;
                            kernel_db.save_tlv_from_card(APPLICATION_CRYPTOGRAM_9F26.id, begin, begin + 8, false);
                            begin += 8;
                            if (begin < end) {
                                kernel_db.save_tlv_from_card(ISSUER_APPLICATION_DATA_9F10.id, begin, end, false);
                            }
                            return true;
                        }
                    };
                    parse_result = tlv_visit(apdu.begin(), apdu.end() - 2, parser);
                }

                // S11.9
                if (!parse_result) {
                    // S11.10
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::PARSING_ERROR);
                    return s11_invalid_response_1(builder);
                }

                // S11.18
                if (!(kernel_db.has_non_empty_tag(ATC_9F36) &&
                      kernel_db.has_non_empty_tag(CID_9F27))) {
                    // S11.19
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::CARD_DATA_MISSING);
                    return s11_invalid_response_1(builder);
                }

                // S11.20
                auto cid = kernel_db[CID_9F27][0] & 0xC0;
                if (((cid == 0x40) && (kernel_db.ac_type == AC_TYPE::TC)) ||
                    ((cid == 0x80) &&
                     ((kernel_db.ac_type == AC_TYPE::TC) ||
                      (kernel_db.ac_type == AC_TYPE::ARQC))) ||
                    (cid == 0)) {
                    // S11.22
                } else {
                    // S11.21
                    pr_debug("wrong ac type received\n");
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::CARD_DATA_ERROR);
                    return s11_invalid_response_1(builder);
                }

                // save GAC RSP to be needed by CDA later
                kernel_db.saved_gac_rsp = apdu;

                // S11.22
                CONTINUE_AFTER_BR2 = &S11_23;
                return post_gen_ac_balance_reading();
            }
            break;
        }
        case SIGNAL::STOP: // S11.3
        case SIGNAL::DET:  // S11.4
            break;
        case SIGNAL::L1RSP: { // S11.1
                              //S11.11
            auto& torn = emvl2->torn_transactions;
            auto torn_record = torn.find(kernel_db);
            if (!(torn_record->get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write))) {
                torn.remove(torn_record);
            };

            // S11.13, 15
            auto drdol = kernel_db[DRDOL_9F51];
            std::vector<uint8_t> drdol_related_data;
            std::vector<uint8_t> missing_tags;
            build_dol(DRDOL_9F51.id, drdol, kernel_db, drdol_related_data, missing_tags);
            kernel_db.emplace(DRDOL_RELATED_DATA_DF8113.id, drdol_related_data);
            torn.create<KERNEL2_NS>(kernel_db);

            //S11.16
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .ui_on_restart()
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        };
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s9_waiting_for_generate_ac_response_1 = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        switch (sig) {
        case SIGNAL::RA: {
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                // S9.17
                outcome_builder builder{kernel_db};
                builder.error(sw1, sw2);
                return s910_invalid_response_1(builder);
            } else {
                // s9.18
                bool parse_result = false;
                unsigned length = (apdu.size() >= 4) ? apdu[1] : 0;

                if (length > 0 && apdu[0] == 0x77) {
                    parse_result = kernel_db.parse_store_card_response(apdu);
                } else {
                    auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                        int length = end - begin;
                        if (tag != 0x80 ||
                            length < 11 || length > 43 ||
                            kernel_db.has_non_empty_tag(CID_9F27) ||
                            kernel_db.has_non_empty_tag(ATC_9F36) ||
                            kernel_db.has_non_empty_tag(APPLICATION_CRYPTOGRAM_9F26) ||
                            (length > 11 &&
                             kernel_db.has_non_empty_tag(ISSUER_APPLICATION_DATA_9F10))) {
                            return false;
                        } else {
                            kernel_db.save_tlv_from_card(CID_9F27.id, begin, begin + 1, false);
                            begin += 1;
                            kernel_db.save_tlv_from_card(ATC_9F36.id, begin, begin + 2, false);
                            begin += 2;
                            kernel_db.save_tlv_from_card(APPLICATION_CRYPTOGRAM_9F26.id, begin, begin + 8, false);
                            begin += 8;
                            if (begin < end) {
                                kernel_db.save_tlv_from_card(ISSUER_APPLICATION_DATA_9F10.id, begin, end, false);
                            }
                            return true;
                        }
                    };
                    parse_result = tlv_visit(apdu.begin(), apdu.end() - 2, parser);
                }

                if (!parse_result) {
                    // S9.20
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::PARSING_ERROR);
                    return s910_invalid_response_1(builder);
                }

                // S9.21
                if (!(kernel_db.has_non_empty_tag(ATC_9F36) &&
                      kernel_db.has_non_empty_tag(CID_9F27))) {
                    // S9.22
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::CARD_DATA_MISSING);
                    return s910_invalid_response_1(builder);
                }

                auto cid = kernel_db[CID_9F27][0] & 0xC0;
                if (((cid == 0x40) && (kernel_db.ac_type == AC_TYPE::TC)) ||
                    ((cid == 0x80) &&
                     ((kernel_db.ac_type == AC_TYPE::TC) ||
                      (kernel_db.ac_type == AC_TYPE::ARQC))) ||
                    (cid == 0)) {
                    // S9.25
                } else {
                    // S9.24
                    pr_debug("wrong ac type received\n");
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::CARD_DATA_ERROR);
                    return s910_invalid_response_1(builder);
                }

                // save GAC RSP to be needed by CDA later
                kernel_db.saved_gac_rsp = apdu;

                // S9.25
                CONTINUE_AFTER_BR2 = &S9_26;
                return post_gen_ac_balance_reading();
            };

            break;
        };
        case SIGNAL::STOP:
        case SIGNAL::DET: // ignore in S9
            break;
        case SIGNAL::L1RSP:
            handle_l1rsp_for_gac(static_cast<L1_ERROR>((*param)[0]));
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(void)> S9_26 = [&]() {
        // S9.26
        if (!kernel_db.has_non_empty_tag(TAGS_TO_WRITE_AFTER_GEN_AC_FF8103)) {
            // S9.27
            outcome_builder builder{kernel_db};
            builder.ui(ui_message_id::NO_MESSAGE, ui_status_id::CARD_READ_OK).hold().msg();
        }

        // S9.28
        if (kernel_db.has_non_empty_tag(SDAD_9F4B)) {
            // S910.1
            return s910_cda();
        } else {
            // S910.30
            return s910_no_cda();
        }

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(void)> S11_23 = [&]() {
        // S11.23
        if (!kernel_db.has_non_empty_tag(TAGS_TO_WRITE_AFTER_GEN_AC_FF8103)) {
            // 11.24
            outcome_builder builder{kernel_db};
            builder.ui(ui_message_id::NO_MESSAGE, ui_status_id::CARD_READ_OK).hold().msg();
        }

        // S11.25
        if (kernel_db.has_non_empty_tag(SDAD_9F4B)) {
            // S11.40
            return s11_cda();
        } else {
            // S11.70
            return s11_no_cda();
        }

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(void)>* CONTINUE_AFTER_BR2;

    KSTATUS s11_cda() {
        // S11.40
        std::vector<uint8_t> icc_modulus{};
        if (emvl2->retrieve_icc_pk(kernel_db, icc_modulus, kernel_db.static_oda_data) &&
            emvl2->verify_cda(kernel_db, icc_modulus, kernel_db.saved_gac_rsp, true)) {
            if (kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
                // S11.45
                return s11_check_ids();
            } else {
                // S11.44
                return s11_valid_response();
            }
        }

        // S11.46
        outcome_builder builder{kernel_db};
        builder.error(L2_ERROR::CAM_FAILED);
        kernel_db.set_bit(TVR_95, TAG_TVR_95::cda_failed);
        return s11_invalid_response_1(builder);
    };

    KSTATUS s910_cda() {
        std::vector<uint8_t> icc_modulus{};
        if (emvl2->retrieve_icc_pk(kernel_db, icc_modulus, kernel_db.static_oda_data) &&
            emvl2->verify_cda(kernel_db, icc_modulus, kernel_db.saved_gac_rsp, true)) {
            if (kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
                // S910.5
                return s910_check_ids();
            } else {
                // S910.6
                return s910_valid_response();
            }
        }

        // S910.7
        outcome_builder builder{kernel_db};
        builder.error(L2_ERROR::CAM_FAILED);
        kernel_db.set_bit(TVR_95, TAG_TVR_95::cda_failed);
        return s910_invalid_response_1(builder);
    };

    // S11.47
    KSTATUS s11_check_ids() {
        auto& torn = emvl2->torn_transactions;
        auto torn_record = torn.find(kernel_db);
        if (torn_record->get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write)) {
            // S11.48
            if (kernel_db[DS_SUMMARY_1_9F7D] != (*torn_record)[DS_SUMMARY_1_9F7D]) {
                // S11.49
                outcome_builder builder{kernel_db};
                builder.error(L2_ERROR::IDS_READ_ERROR);
                return s11_invalid_response_1(builder);
            }
        }

        // S11.50
        if (!kernel_db.has_tag(DS_SUMMARY_2_DF8101.id)) {
            // S11.51
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::CARD_DATA_MISSING);
            return s11_invalid_response_1(builder);
        }

        // S11.52
        if (kernel_db[DS_SUMMARY_1_9F7D] != kernel_db[DS_SUMMARY_2_DF8101]) {
            // S11.53
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::IDS_READ_ERROR);
            return s11_invalid_response_1(builder);
        }

        // S11.54
        kernel_db.set_bit(DS_SUMMARY_STATUS_DF810B, TAG_DS_SUMMARY_STATUS_DF810B::read);

        // S11.55
        if (!kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write)) {
            // S11.110
            return s11_valid_response();
        }

        // S11.56
        if (!kernel_db.has_tag(DS_SUMMARY_3_DF8102)) {
            // S910.57
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::CARD_DATA_MISSING);
            return s11_invalid_response_1(builder);
        }

        // S11.58
        if (kernel_db[DS_SUMMARY_3_DF8102] != kernel_db[DS_SUMMARY_2_DF8101]) {
            // S11.59
            kernel_db.set_bit(DS_SUMMARY_STATUS_DF810B, TAG_DS_SUMMARY_STATUS_DF810B::write);
        } else if (kernel_db.get_bit(DS_ODS_INFO_FOR_READER_DF810A, TAG_DS_ODS_INFO_FOR_READER_DF810A::stop_if_write_failed)) { // S11.60
                                                                                                                                // S11.61
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::IDS_WRITE_ERROR);
            return s11_invalid_response_2(builder);
        };

        return s11_valid_response();
    };

    // S910.8
    KSTATUS s910_check_ids() {
        if (!kernel_db.has_non_empty_tag(DS_SUMMARY_2_DF8101.id)) {
            // S910.9
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::CARD_DATA_MISSING);
            return s910_invalid_response_1(builder);
        }

        // S910.10
        if (kernel_db[DS_SUMMARY_1_9F7D] != kernel_db[DS_SUMMARY_2_DF8101]) {
            // S910.11
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::IDS_READ_ERROR);
            return s910_invalid_response_1(builder);
        }

        // S910.12
        kernel_db.set_bit(DS_SUMMARY_STATUS_DF810B, TAG_DS_SUMMARY_STATUS_DF810B::read);

        // S910.13
        if (!kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::write)) {
            return s910_valid_response();
        }

        if (!kernel_db.has_tag(DS_SUMMARY_3_DF8102)) {
            // S910.15
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::CARD_DATA_MISSING);
            return s910_invalid_response_1(builder);
        }

        //  S910.16
        if (kernel_db[DS_SUMMARY_3_DF8102] != kernel_db[DS_SUMMARY_2_DF8101]) {
            kernel_db.set_bit(DS_SUMMARY_STATUS_DF810B, TAG_DS_SUMMARY_STATUS_DF810B::write);
        } else if (kernel_db.get_bit(DS_ODS_INFO_FOR_READER_DF810A, TAG_DS_ODS_INFO_FOR_READER_DF810A::stop_if_write_failed)) {
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::IDS_WRITE_ERROR);
            return s910_invalid_response_2(builder);
        };

        return s910_valid_response();
    };

    void prepare_outcome_on_cid(outcome_builder& builder) {
        // S910.74
        auto cid = kernel_db(CID_9F27);
        if (cid == AC_TYPE::TC) {
            builder.status(OUTCOME_TYPE::APPROVED);
        } else {
            if (cid == AC_TYPE::ARQC) {
                builder.status(OUTCOME_TYPE::ONLINE_REQUEST);
            } else {
                auto transact_type = kernel_db(TRANSACTION_TYPE_9C);
                if (transact_type == TRANSACTION_TYPE::CASH ||
                    transact_type == TRANSACTION_TYPE::CASH_DISBURSEMENT ||
                    transact_type == TRANSACTION_TYPE::PURCHASE ||
                    transact_type == TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK) {
                    builder.status(OUTCOME_TYPE::TRY_ANOTHER_INTERFACE);
                    if (!kernel_db.get_bit(TERMINAL_CAPABILITIES_9F33, TAG_TERMINAL_CAPABILITIES_9F33::icc_with_contacts)) {
                        builder.status(OUTCOME_TYPE::DECLINED);
                    } else if (kernel_db.has_non_empty_tag(THIRD_PARTY_DATA_9F6E)) {
                        auto& v = kernel_db[THIRD_PARTY_DATA_9F6E];
                        if (TAG_THIRD_PARTY_DATA_9F6E::has_device_type(v)) {
                            auto device_type = TAG_THIRD_PARTY_DATA_9F6E::get_device_type(v);
                            if (device_type[0] != 0x30 || device_type[1] != 0x30) {
                                builder.status(OUTCOME_TYPE::DECLINED);
                            }
                        }
                    }
                } else {
                    builder.status(OUTCOME_TYPE::END_APPLICATION);
                }
            }
        }
    }

    void prepare_ui_on_cid(outcome_builder& builder){
        // S910.75
        builder.ui(ui_status_id::NOT_READY);
        auto cid = kernel_db(CID_9F27);
        if (cid == AC_TYPE::TC) {
            builder.hold(kernel_db[MESSAGE_HOLD_TIME_DF812D]);
            if (kernel_db.has_non_empty_tag(BALANCE_READ_AFTER_GEN_AC_DF8105)) {
                builder.ui(ui_value_id::BALANCE, kernel_db[BALANCE_READ_AFTER_GEN_AC_DF8105]);
                if (kernel_db.has_non_empty_tag(APPLICATION_CURRENCY_CODE_9F42)) {
                    builder.currency(kernel_db[APPLICATION_CURRENCY_CODE_9F42]);
                }
            };
            if (TAG_OUTCOME_PARAMETER_SET_DF8129::get_cvm(kernel_db[OUTCOME_PARAMETER_SET_DF8129]) == OUTCOME_CVM::SIGNATURE) {
                builder.ui(ui_message_id::APPROVED_PLEASE_SIGN);
            } else {
                builder.ui(ui_message_id::APPROVED);
            }
        } else {
            if (cid == AC_TYPE::ARQC) {
                builder.hold().ui(ui_message_id::AUTHORISING);
            } else {
                auto transact_type = kernel_db(TRANSACTION_TYPE_9C);
                if (transact_type == TRANSACTION_TYPE::CASH ||
                    transact_type == TRANSACTION_TYPE::CASH_DISBURSEMENT ||
                    transact_type == TRANSACTION_TYPE::PURCHASE ||
                    transact_type == TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK) {
                    builder.hold(kernel_db[MESSAGE_HOLD_TIME_DF812D]);
                    builder.ui(ui_message_id::INSERT_CARD);
                    if (!kernel_db.get_bit(TERMINAL_CAPABILITIES_9F33, TAG_TERMINAL_CAPABILITIES_9F33::icc_with_contacts)) {
                        builder.ui(ui_message_id::NOT_AUTHORIZED);
                    } else if (kernel_db.has_non_empty_tag(THIRD_PARTY_DATA_9F6E)) {
                        auto& v = kernel_db[THIRD_PARTY_DATA_9F6E];
                        if (TAG_THIRD_PARTY_DATA_9F6E::has_device_type(v)) {
                            auto device_type = TAG_THIRD_PARTY_DATA_9F6E::get_device_type(v);
                            if (device_type[0] != 0x30 || device_type[1] != 0x30) {
                                builder.ui(ui_message_id::NOT_AUTHORIZED);
                            }
                        }
                    }
                } else {
                    builder.hold().ui(ui_message_id::NO_MESSAGE);
                }
            }
        }
    };

    // S11.110
    KSTATUS s11_valid_response() {
        // S11.110
        return s910_valid_response();
    };

    KSTATUS s910_valid_response() {
        // S910.70
        outcome_builder builder{kernel_db};
        builder.create_emv_dr<KERNEL2_NS>();

        bool second_tap = false;
        // S910.71
        if (kernel_db.has_non_empty_tag(POS_CARDHOLDER_INTERACTION_INFO_DF4B)) {
            auto& pcii = kernel_db[POS_CARDHOLDER_INTERACTION_INFO_DF4B];
            if ((pcii[1] & 0x03) || (pcii[2] & 0x0F))
                second_tap = true;
        }

        if (second_tap) {
            // S910.72
            builder.status(OUTCOME_TYPE::END_APPLICATION)
                .start(RESTART_POINT::B);

            // S910.73
            auto& table = kernel_db[PHONE_MESSAGE_TABLE_DF8131];
            for (auto p = table.data(); p < table.data() + table.size(); p += 8) {
                auto& pcii = kernel_db[POS_CARDHOLDER_INTERACTION_INFO_DF4B];
                if ((p[0] & pcii[0]) == p[3] &&
                    (p[1] & pcii[1]) == p[4] &&
                    (p[2] & pcii[2]) == p[5]) {
                    builder.hold(kernel_db[MESSAGE_HOLD_TIME_DF812D])
                        .ui(static_cast<ui_message_id>(p[6]), static_cast<ui_status_id>(p[7]));
                    break;
                }
            };
        } else {
            // S910.74
            prepare_outcome_on_cid(builder);

            // S910.75
            prepare_ui_on_cid(builder);
        }

        // S910.76
        if (!kernel_db.tags_to_write_yet_after_gen_ac.empty()) {
            // S910.77, 78
            auto tlv = kernel_db.tags_to_write_yet_after_gen_ac.get_and_remove_from_list();
            uint32_t tag = tlv.first;
            uint8_t p1 = static_cast<uint8_t>((tag >> 8) & 0xFF);
            uint8_t p2 = static_cast<uint8_t>((tag)&0xFF);
            emvl2->send_apdu(apdu_builder::build(COMMANDS::PUT_DATA).data(tlv.second).p1(p1).p2(p2).to_bytes());
            enter_state(&s15_waiting_for_put_data_response_after_gen_ac);
            return KSTATUS::DEFAULT;
        }

        if (second_tap) {
            // S910.79, 80
            emvl2->generate_outcome(builder.msg()
                                        .create_emv_dd<KERNEL2_NS>()
                                        .ui_on_restart()
                                        .ui(ui_status_id::PRESENT_CARD)
                                        .hold()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DATA_RECORD_FF8105)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());

        } else {
            // S910.81
            emvl2->generate_outcome(builder.create_emv_dd<KERNEL2_NS>()
                                        .ui_on_outcome()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DATA_RECORD_FF8105)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
        }

        return KSTATUS::EXIT_KERNEL;
    };

    KSTATUS s11_no_cda() {
        return KSTATUS::DEFAULT;
    };

    KSTATUS s910_no_cda() {
        // S910.30
        if (!kernel_db.has_non_empty_tag(APPLICATION_CRYPTOGRAM_9F26)) {
            // S910.31
            outcome_builder builder{kernel_db};
            builder.error(L2_ERROR::CARD_DATA_MISSING);
            return s910_invalid_response_1(builder);
        }

        auto cid = kernel_db[CID_9F27][0] & 0xC0;
        auto& refctrl = kernel_db[REFERENCE_CONTROL_PARAMETER_DF8114];

        if (cid == 0x00) {
            if (!kernel_db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
                if (TAG_REFERENCE_CONTROL_PARAMETER_DF8114::get_ac_type(refctrl) != AC_TYPE::AAC ||
                    !v_get_bit(refctrl, TAG_REFERENCE_CONTROL_PARAMETER_DF8114::cda_signature_requested)) {
                    return s910_valid_response();
                }
            }
        } else if (!v_get_bit(refctrl, TAG_REFERENCE_CONTROL_PARAMETER_DF8114::cda_signature_requested)) {
            // S910.38
            if (TAG_TVR_95::get_rrp(kernel_db[TVR_95]) == TAG_TVR_95::RRP_STATUS::PERFORMED) {
                // S910.39
                if (kernel_db.has_non_empty_tag(TRACK2_57)) {
                    auto& track2 = kernel_db[TRACK2_57];
                    auto pan = TAG_TRACK2_57::get_pan(track2);
                    std::string dd{};
                    if (pan.size() <= 16)
                        dd = std::string("0000000000000");
                    else
                        dd = std::string("0000000000");

                    if (kernel_db.has_non_empty_tag(CA_PUBLIC_KEY_INDEX_8F)) {
                        uint8_t index = kernel_db[CA_PUBLIC_KEY_INDEX_8F][0];
                        if (index < 0x0A) {
                            dd[0] = index + '0';
                        }
                    }

                    dd[1] = static_cast<char>(kernel_db[RRP_COUNTER_DF8307][0] + '0');
                    auto entropy = kernel_db[DEVIDE_REPLAY_RESISTENCE_ENTROPY_DF8302];
                    auto entropy_digits = to_decimal((entropy[2] << 8) + entropy[3], 5);
                    std::copy(entropy_digits.begin(), entropy_digits.end(), dd.begin() + 2);
                    if (pan.size() <= 16) {
                        auto digits = to_decimal(entropy[1], 3);
                        std::copy(digits.begin(), digits.end(), dd.begin() + 7);
                    };

                    auto time = kernel_db[MEASURED_RELAY_RESISTENCE_PROCESSING_TIME_DF8306];
                    auto msecs = ((time[0] << 8) + time[1]) / 10;
                    if (msecs > 999)
                        msecs = 999;
                    auto msecs_digits = to_decimal(msecs);
                    std::copy(msecs_digits.rbegin(), msecs_digits.rend(), dd.rend());
                    auto paddings = 38 - pan.size() - 8 - dd.size();
                    while (paddings)
                        dd.push_back('F');
                    TAG_TRACK2_57::set_dd(track2, dd);
                }
            }
            return s910_valid_response();
        }

        outcome_builder builder{kernel_db};
        builder.error(L2_ERROR::CARD_DATA_ERROR);
        return s910_invalid_response_1(builder);
    };

    // section 7.1
    KSTATUS pre_gen_ac_balance_reading() {
        if (kernel_db.has_non_empty_tag(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D) &&
            kernel_db.get_bit(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D, KERNEL2::TAG_APPLICATION_CAPABILITIES_INFO_9F5D::support_for_balance_reading) &&
            kernel_db.has_tag(BALANCE_READ_BEFORE_GEN_AC_DF8104)) {
            // BR1.3
            // Read TAG "Offline Accumulator Balance"
            pr_debug("pre-gen-ac reading offline balance\n");
            emvl2->send_apdu(apdu_builder::build(COMMANDS::GET_DATA).p1(0x9F).p2(0x50).le(0).to_bytes());
            enter_state(&s16_waiting_for_pre_gen_ac_balance);
            return KSTATUS::DEFAULT;
        }

        return CONTINUE_AFTER_BR1();
    };

    // section 7.3
    KSTATUS post_gen_ac_balance_reading() {
        if (kernel_db.has_non_empty_tag(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D) &&
            kernel_db.get_bit(KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D, KERNEL2::TAG_APPLICATION_CAPABILITIES_INFO_9F5D::support_for_balance_reading) &&
            kernel_db.has_tag(BALANCE_READ_AFTER_GEN_AC_DF8105)) {
            pr_debug("post-gen-ac reading offline balance\n");
            emvl2->send_apdu(apdu_builder::build(COMMANDS::GET_DATA).p1(0x9F).p2(0x50).le(0).to_bytes());
            enter_state(&s17_waiting_for_post_gen_ac_balance);
            return KSTATUS::DEFAULT;
        }

        return (*CONTINUE_AFTER_BR2)();
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s10_waiting_for_recover_ac_response = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug(std::string("enter s10_waiting_for_recover_ac_response\n"));
        switch (sig) {
        case SIGNAL::RA: { // S10.2
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            // S10.7
            if (sw1 != 0x90 || sw2 != 0x00) {
                // S10.8, 9
                auto ret = generate_ac(); // section 7.6
                if (ret != KSTATUS::DEFAULT)
                    return ret;
                enter_state(&s11_waiting_for_gen_ac_response_2);
            } else {
                // S10.10, 11
                auto& torn = emvl2->torn_transactions;
                auto torn_record = torn.find(kernel_db);
                for (auto iter = torn_record->begin(); iter != torn_record->end(); iter++) {
                    if (tag_is_primitive(iter->first))
                        kernel_db.update(*iter);
                };
                torn.remove(torn_record);

                // S10.12
                bool parse_result = false;
                if (apdu.size() > 2 && apdu[0] == 0x77) {
                    parse_result = kernel_db.parse_store_card_response(apdu);
                }

                // S10.13
                if (!parse_result) {
                    // S10.14
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::PARSING_ERROR);
                    return s910_invalid_response_1(builder);
                }

                // S10.15
                if (!(kernel_db.has_non_empty_tag(ATC_9F36) &&
                      kernel_db.has_non_empty_tag(CID_9F27))) {
                    // S10.16
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::CARD_DATA_MISSING);
                    return s910_invalid_response_1(builder);
                }

                // S10.17
                auto cid = kernel_db[CID_9F27][0] & 0xC0;
                if (!(((cid == 0x40) && (kernel_db.ac_type == AC_TYPE::TC)) ||
                      ((cid == 0x80) &&
                       ((kernel_db.ac_type == AC_TYPE::TC) ||
                        (kernel_db.ac_type == AC_TYPE::ARQC))) ||
                      (cid == 0))) {
                    // S10.18
                    pr_debug("wrong ac type received\n");
                    outcome_builder builder{kernel_db};
                    builder.error(L2_ERROR::CARD_DATA_ERROR);
                    return s910_invalid_response_1(builder);
                }

                // save RECOVER_AC RSP to be needed by CDA later
                kernel_db.saved_gac_rsp = apdu;

                // S10.19
                CONTINUE_AFTER_BR2 = &S9_26;
                return post_gen_ac_balance_reading();
            };
            break;
        };
        case SIGNAL::STOP: // S10.4
        case SIGNAL::DET:  // S10.3
            break;
        case SIGNAL::L1RSP: { // S10.1
            //S10.5, 6
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .ui_on_restart()
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        };
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s12_waiting_for_put_data_response_before_generate_ac = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug(std::string("enter s12_waiting_for_put_data_response_before_generate_ac\n"));
        switch (sig) {
        case SIGNAL::RA: { // S12.2
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            // S12.8
            if (sw1 == 0x90 && sw2 == 0x00) {
                // S12.9
                if (!kernel_db.tags_to_write_yet_before_gen_ac.empty()) { // S12.10
                                                                          // S12.11
                    auto tlv = kernel_db.tags_to_write_yet_before_gen_ac.get_and_remove_from_list();
                    uint32_t tag = tlv.first;
                    uint8_t p1 = static_cast<uint8_t>((tag >> 8) & 0xFF);
                    uint8_t p2 = static_cast<uint8_t>((tag)&0xFF);
                    emvl2->send_apdu(apdu_builder::build(COMMANDS::PUT_DATA).data(tlv.second).p1(p1).p2(p2).to_bytes());
                    break;
                }

                // S12.12
                // Pre-Gen AC Put Data Status := Completed
            };

            // S12.13
            if (kernel_db.has_non_empty_tag(DRDOL_9F51) &&
                kernel_db[MAX_NUMBER_OF_TORN_RECORDS_DF811D][0] != 0) {
                // S12.14
                auto& torn = emvl2->torn_transactions;
                auto p = torn.find(kernel_db);
                if (p != torn.cend()) {
                    // S12.17, 18, 19
                    pr_debug("find torn transaction\n");
                    auto drdol = kernel_db[DRDOL_9F51];
                    std::vector<uint8_t> drdol_related_data;
                    std::vector<uint8_t> missing_tags;
                    build_dol(DRDOL_9F51.id, drdol, *p, drdol_related_data, missing_tags);

                    emvl2->send_apdu(apdu_builder::build(COMMANDS::RECOVER_AC).le(0).data(drdol_related_data).to_bytes());
                    enter_state(&s10_waiting_for_recover_ac_response);
                    return KSTATUS::DEFAULT;
                }
            }

            // S12.15, 16
            auto ret = generate_ac();
            if (ret != KSTATUS::DEFAULT)
                return ret;

            enter_state(&s9_waiting_for_generate_ac_response_1);

            return KSTATUS::DEFAULT;
        }
        case SIGNAL::STOP: { // S12.3
                             // S12.7
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());

            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::DET: // S12.4
            break;

        case SIGNAL::L1RSP: { // S12.1
                              // S12.5, 6
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .ui_on_restart()
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        default:
            break;
        }

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s15_waiting_for_put_data_response_after_gen_ac = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug(std::string("enter s15_waiting_for_put_data_response_after_gen_ac\n"));
        switch (sig) {
        case SIGNAL::RA: { // S15.2
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            // S15.5
            if (sw1 == 0x90 && sw2 == 0x00) {
                // S15.6
                if (!kernel_db.tags_to_write_yet_before_gen_ac.empty()) {
                    // S15.7,8
                    auto tlv = kernel_db.tags_to_write_yet_before_gen_ac.get_and_remove_from_list();
                    uint32_t tag = tlv.first;
                    uint8_t p1 = static_cast<uint8_t>((tag >> 8) & 0xFF);
                    uint8_t p2 = static_cast<uint8_t>((tag)&0xFF);
                    emvl2->send_apdu(apdu_builder::build(COMMANDS::PUT_DATA).data(tlv.second).p1(p1).p2(p2).to_bytes());
                    return KSTATUS::DEFAULT;
                }

                // S15.9
                // Post-Gen AC Put Data Status := Completed
            };
            break;
        }
        case SIGNAL::STOP:   // S15.3
        case SIGNAL::DET:    // S15.4
            return KSTATUS::DEFAULT;

        case SIGNAL::L1RSP: // S15.1
            break;
        default:
            return KSTATUS::DEFAULT;
        }

        // S15.9.1
        bool second_tap = false;
        if (kernel_db.has_non_empty_tag(POS_CARDHOLDER_INTERACTION_INFO_DF4B)) {
            auto& pcii = kernel_db[POS_CARDHOLDER_INTERACTION_INFO_DF4B];
            if ((pcii[1] & 0x03) || (pcii[2] & 0x0F))
                second_tap = true;
        }

        outcome_builder builder{kernel_db};
        if (second_tap) {
            // S15.10, 11
            emvl2->generate_outcome(builder.ui(ui_status_id::CARD_READ_OK)
                                        .msg()
                                        .create_emv_dd<KERNEL2_NS>()
                                        .ui_on_restart()
                                        .ui(ui_status_id::PRESENT_CARD)
                                        .hold()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DATA_RECORD_FF8105)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
        } else {
            // S15.12, 13
            tlv_db db{};
            outcome_builder display{db};
            display.ui(ui_message_id::NO_MESSAGE, ui_status_id::CARD_READ_OK).hold().msg();

            emvl2->generate_outcome(builder.create_emv_dd<KERNEL2_NS>()
                                        .ui_on_outcome()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DATA_RECORD_FF8105)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
        }

        return KSTATUS::EXIT_KERNEL;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s16_waiting_for_pre_gen_ac_balance = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug(std::string("enter s16_waiting_for_pre_gen_ac_balance\n"));

        switch (sig) {
        case SIGNAL::RA: { // S16.4
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                if (apdu.size() == 11) {
                    // S16.8
                    if (apdu[0] == 0x9F && apdu[1] == 0x50 &&
                        apdu[2] == 0x06) {
                        auto& v = kernel_db[BALANCE_READ_AFTER_GEN_AC_DF8105];
                        v = std::vector<uint8_t>(apdu.begin() + 3, apdu.begin() + 9);
                    }
                }
            };
            break;
        }
        case SIGNAL::STOP: { // S16.6
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());

            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::DET:  // S16.5
            return KSTATUS::DEFAULT;

        case SIGNAL::L1RSP: { // 16.1
                              // S16.2,3
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::TRY_AGAIN, ui_status_id::PRESENT_CARD)
                                        .hold()
                                        .start(RESTART_POINT::B)
                                        .ui_on_restart()
                                        .error(static_cast<L1_ERROR>((*param)[0]))
                                        .msg_on_error(ui_message_id::TRY_AGAIN)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        default:
            break;
        }

        return CONTINUE_AFTER_BR1();
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s17_waiting_for_post_gen_ac_balance = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        switch (sig) {
        case SIGNAL::RA: { // S17.2
            auto& apdu = *param;
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 != 0x90 || sw2 != 0x00) {
                if (apdu.size() == 11) {
                    // S17.6
                    if (apdu[0] == 0x9F && apdu[1] == 0x50 &&
                        apdu[2] == 0x06) {
                        auto& v = kernel_db[BALANCE_READ_AFTER_GEN_AC_DF8105];
                        v = std::vector<uint8_t>(apdu.begin() + 3, apdu.begin() + 9);
                    }
                }
            };
            break;
        }
        case SIGNAL::STOP: // S17.3
        case SIGNAL::DET:  // S17.4
            return KSTATUS::DEFAULT;
        case SIGNAL::L1RSP: // 17.1
        default:
            break;
        }

        return (*CONTINUE_AFTER_BR2)();
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s6_wait_for_emv_mode_first_write_flag = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug(std::string("enter s6_wait_for_emv_mode_first_write_flag\n"));
        switch (sig) {
        case SIGNAL::TIMEOUT: { // S6.1
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::TIME_OUT)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::STOP: { // S6.2
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::DET: { // S6.5
            // S6.6
            kernel_db.update_with_det_data(*param);

            // S6.7
            stop_time_out();

            // S6.8
            NEXT_CMD next_cmd = NEXT_CMD::NONE;
            auto active_tag = kernel_db.tags_to_read_yet.begin();
            if (active_tag != kernel_db.tags_to_read_yet.end()) {
                // S6.9
                uint8_t p1 = static_cast<uint8_t>((*active_tag >> 8) & 0xFF);
                uint8_t p2 = static_cast<uint8_t>((*active_tag) & 0xFF);

                // S6.10
                emvl2->send_apdu(apdu_builder::build(COMMANDS::GET_DATA).p1(p1).p2(p2).le(0).to_bytes());
                // S6.11
                next_cmd = NEXT_CMD::GET_DATA;
            }
            return s456(next_cmd);
        }
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s4_terminate_on_next_ra = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        pr_debug(std::string("enter s4_terminate_on_next_ra\n"));
        switch (sig) {
        case SIGNAL::RA:      // S4'.1
        case SIGNAL::L1RSP: { // S4'.2
                              // S4'.4.1, 2
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .ui(ui_message_id::INSERT_SWIPE_TRY_ANOTHER, ui_status_id::NOT_READY)
                                        .ui_on_outcome()
                                        .error(L2_ERROR::PARSING_ERROR)
                                        .msg_on_error(ui_message_id::INSERT_SWIPE_TRY_ANOTHER)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .pack(USER_INTERFACE_REQUEST_DATA_DF8116)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::STOP: { // S4'.3
                             // S4'.5
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .create_emv_dd<KERNEL2_NS>()
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());
            return KSTATUS::EXIT_KERNEL;
        }
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    KSTATUS send_rrp_data() {
        tlv_obj entropy{DEVIDE_REPLAY_RESISTENCE_ENTROPY_DF8302.id,
                        kernel_db[UNPREDICTABLE_NUMBER_9F37]};
        kernel_db.insert(std::move(entropy));

        // TODO
        pr_warn("S3.62 send rrp NOT IMPLEMENTED\n");
        return KSTATUS::DEFAULT;
    };

    std::vector<uint8_t> get_rid() {
        std::vector<uint8_t> rid{};
        auto& p = kernel_db[ADF_NAME_4F];
        std::copy(p.begin(), p.begin() + 5, back_inserter(rid));

        return rid;
    };

    KSTATUS s456(NEXT_CMD next_cmd) {
        switch (next_cmd) {
        case NEXT_CMD::NONE:
            // S456.5
            if (kernel_db.has_empty_tag(PROCEED_TO_FIRST_WRITE_FLAG_DF8110.id)) {
                auto& data_needed = kernel_db[DATA_NEEDED_DF8106];

                auto tag = tag_in_bytes(PROCEED_TO_FIRST_WRITE_FLAG_DF8110.id);
                std::copy(tag.begin(), tag.end(), std::back_inserter(data_needed));
            } else if (kernel_db.has_tag(PROCEED_TO_FIRST_WRITE_FLAG_DF8110) &&
                       kernel_db[PROCEED_TO_FIRST_WRITE_FLAG_DF8110][0] != 0) {
                return proceed_to_write();
            }
            drain_tags_to_read_yet();
            if (kernel_db.has_non_empty_tag(DATA_NEEDED_DF8106) ||
                (kernel_db.has_non_empty_tag(DATA_TO_SEND_FF8104) &&
                 kernel_db.tags_to_read_yet.size() == 0)) {
                send_dek();
            }
            start_time_out();
            enter_state(&s6_wait_for_emv_mode_first_write_flag);
            break;

        case NEXT_CMD::GET_DATA:
        case NEXT_CMD::READ_RECORD:
            // S456.2
            drain_tags_to_read_yet();
            if (kernel_db.has_non_empty_tag(DATA_TO_SEND_FF8104) &&
                kernel_db.tags_to_read_yet.size() == 0) {
                send_dek();
            }
            enter_state(&s4_wait_for_emv_read_record);
            break;
        };

        return KSTATUS::DEFAULT;
    };

    //s3.70
    KSTATUS handle_ms_mode() {
        static const uint8_t default_one[] = {0x08, 0x01, 0x01, 0x00};
        auto& afl = kernel_db[AFL_94];
        if (afl.size() >= 4 &&
            memcmp(afl.data(), default_one, 4)) {
            //S3.72
            kernel_db.afl = std::vector<uint8_t>(afl.cbegin(), afl.cbegin() + 4);
        } else {
            //S3.71
            kernel_db.afl = afl;
        }

        auto& aip = kernel_db[AIP_82];
        auto& kcfg = kernel_db[KERNEL_CONFIGURATION_DF811B];
        if (v_get_bit(aip, TAG_AIP_82::on_device_cardholder_verification_supported) &&
            v_get_bit(kcfg, TAG_KERNEL_CONFIGURATION_DF811B::on_device_verification_supported)) {
            // S3.75
            kernel_db.contactless_transaction_limit = kernel_db[READER_CONTACTLESS_TRANSACTION_LIMIT_ON_DEVICE_CVM_DF8125];
        } else {
            // S3.74
            kernel_db.contactless_transaction_limit = kernel_db[READER_CONTACTLESS_TRANSACTION_LIMIT_NO_ON_DEVICE_CVM_DF8124];
        };

        drain_tags_to_read_yet();
        if (kernel_db.has_non_empty_tag(DATA_NEEDED_DF8106) ||
            (kernel_db.has_non_empty_tag(DATA_TO_SEND_FF8104) &&
             kernel_db.tags_to_read_yet.size() == 0)) {
            // S3.78
            send_dek();
        }

        // S3.80, 81
        kernel_db.init_card_read();
        kernel_db.read_next_record(emvl2);
        enter_state(&s7_wait_for_ms_read_record);
        return KSTATUS::DEFAULT;
    };

    std::function<KSTATUS(SIGNAL, const std::vector<uint8_t>*)> s2_wait_for_pdol_data = [&](SIGNAL sig, const std::vector<uint8_t>* param) {
        switch (sig) {
        case SIGNAL::TIMEOUT: {
            // s2.3
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::TIME_OUT)
                                        .initialize(DISCRETIONARY_DATA_FF8106)
                                        .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());

            return KSTATUS::EXIT_KERNEL;

            break;
        }
        case SIGNAL::STOP: {
            // s2.4
            outcome_builder builder{kernel_db};
            emvl2->generate_outcome(builder.status(OUTCOME_TYPE::END_APPLICATION)
                                        .error(L3_ERROR::STOP)
                                        .initialize(DISCRETIONARY_DATA_FF8106)
                                        .add_to_list(ERROR_INDICATION_DF8115, DISCRETIONARY_DATA_FF8106)
                                        .pack(OUTCOME_PARAMETER_SET_DF8129)
                                        .pack(DISCRETIONARY_DATA_FF8106)
                                        .post());

            return KSTATUS::EXIT_KERNEL;
        }
        case SIGNAL::DET:
            // s2.5
            kernel_db.update_with_det_data(*param);
            break;
        default:
            break;
        };

        return KSTATUS::DEFAULT;
    };

    void send_dek() {
        std::vector<uint8_t> data{};
        if (kernel_db.has_non_empty_tag(DATA_NEEDED_DF8106.id)) {
            auto v = kernel_db.to_tlv(DATA_NEEDED_DF8106);
            std::copy(v.begin(), v.end(), back_inserter(data));
        }

        if (kernel_db.has_non_empty_tag(DATA_TO_SEND_FF8104.id)) {
            auto v = kernel_db.to_tlv(DATA_TO_SEND_FF8104);
            std::copy(v.begin(), v.end(), back_inserter(data));
        }

        pr_debug("send dek ", data, "\n");
        message out{MESSAGE_ID::DEK, EMV_MODULE::L2, EMV_MODULE::TERMINAL, data};
        out.send();
        kernel_db.initialize(DATA_NEEDED_DF8106);
        kernel_db.initialize(DATA_TO_SEND_FF8104);
    };

    void start_time_out() {
        auto& timeout = kernel_db[TIME_OUT_VALUE_DF8127];
        int msecs = (timeout[0] << 8) + timeout[1];
        k2resp.start_timer(msecs);
    };

    void stop_time_out() {
        k2resp.stop_timer();
    };
};
}; // namespace emv::contactless

#endif

