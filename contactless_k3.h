/* contactless_k3.h - EVM Contactless Kernel 3 (Visa) implementation
 * Copyright 2019 Daniel Hu <daddy.of.qq@gmail.com>
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

#ifndef CONTACTLESS_K3_H
#define CONTACTLESS_K3_H

#include "emv.h"

namespace emv::contactless {
class kernel3 : public kernel {
    class database : public tlv_db {
    public:
        database() : tlv_db{}, decline_required_by_reader{false}, online_required_by_reader{false}, static_oda_data{secure_vector{}} {};
        bool decline_required_by_reader;
        bool online_required_by_reader;
        secure_vector static_oda_data;
    };

private:
    class read_responder : public modulel2::responder {
    public:
        read_responder(kernel3* k3) : modulel2::responder(0, k3->emvl2), k3{k3} {};
        virtual void handle_apdu(const secure_vector& apdu) override {
            modulel2::responder::handle_apdu(apdu);
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 == 0x90 && sw2 == 0x00) {
                auto parser = [&](uint32_t tag, auto begin, auto end, bool combined) mutable -> bool {
                    if (combined) {
                        auto first = AFL_94.get_first_record(next);
                        auto oda_num = AFL_94.get_oda_records(next);
                        auto sfi = AFL_94.get_sfi(next);
                        pr_debug("\nGot sfi ", static_cast<int>(sfi), " record #", static_cast<int>(next_record), " total oda records ", static_cast<int>(oda_num), "\n");
                        if (first + oda_num > next_record) {
                            if (tag != 0x70) {
                                pr_error("oda data not having tag 0x70\n");
                                return false;
                            } else if (sfi <= 10) {
                                secure_vector data{begin, end};
                                pr_debug("APPEND ", data, "\n");
                                std::copy(begin, end, back_inserter(k3->kernel_db.static_oda_data));
                            }
                        }
                    };
                    return (*k3)(tag, begin, end, combined);
                };

                auto first = AFL_94.get_first_record(next);
                auto oda_num = AFL_94.get_oda_records(next);
                if (first + oda_num > next_record) {
                    auto sfi = AFL_94.get_sfi(next);
                    if (sfi > 10) {
                        pr_debug("sfi ", static_cast<int>(sfi), " record ", static_cast<int>(next_record), "\n");
                        secure_vector data{apdu.begin(), apdu.end() - 2};
                        pr_debug("APPEND ", data, "\n");
                        std::copy(apdu.begin(), apdu.end() - 2, back_inserter(k3->kernel_db.static_oda_data));
                    }
                };
                bool ret = tlv_visit(apdu.begin(), apdu.end() - 2, parser);
                if (!ret) {
                    k3->end_application();
                    return;
                }

                next_record++;
                if (next_record <= AFL_94.get_last_record(next)) {
                    k3->read_card();
                } else {
                    next += 4;
                    if (next >= afl.data() + afl.size()) {
                        k3->complete_read();
                    } else {
                        next_record = AFL_94.get_first_record(next);
                        k3->read_card();
                    }
                }
            } else {
                k3->end_application();
                return;
            }

            return;
        }

        virtual void timeout() override{};

        uint8_t next_record;
        secure_vector afl;
        const uint8_t* next;
        kernel3* k3;
    };

    class gpo_responder : public modulel2::responder {
    public:
        gpo_responder(kernel3* k3) : modulel2::responder(0, k3->emvl2), k3{k3} {};
        virtual void handle_apdu(const secure_vector& apdu) override {
            modulel2::responder::handle_apdu(apdu);
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (sw1 == 0x90 && sw2 == 0x00) {
                auto parser = [&](uint32_t tag, auto begin, auto end, bool combined) mutable -> bool {
                    if (tag == 0x80) { // format 1, always AIP (2 bytes) + AFL
                        if (end - begin >= 2) {
                            auto p = begin + 2;
                            return (*k3)(AIP_82.id, begin, p, false) && (*k3)(AFL_94.id, p, end, false);
                        } else {
                            return false;
                        };
                    } else {
                        return (*k3)(tag, begin, end, combined);
                    };
                };

                bool ret = tlv_visit(apdu.begin(), apdu.end() - 2, parser);
                if (!ret) {
                    k3->end_application();
                    return;
                };

                if (k3->kernel_db.has_tag(AFL_94)) {
                    k3->state_wait_for_read.afl = k3->kernel_db[AFL_94];
                    const uint8_t* next = k3->state_wait_for_read.afl.data();
                    k3->state_wait_for_read.next = next;
                    k3->state_wait_for_read.next_record = AFL_94.get_first_record(next);
                    k3->read_card();
                    return;
                }
                k3->complete_read();
                // start read record
            } else if (sw1 == 0x69 && sw2 == 0x84) { // 5.2.2.2
                k3->try_contact();
            } else if (sw1 == 0x69 && sw2 == 0x85) {
                k3->select_next();
            } else if (sw1 == 0x69 && sw2 == 0x86) {
                k3->end_application();
            };
        }

        virtual void timeout() override{};
        kernel3* k3;
    };

public:
    kernel3(modulel2* emvl2) : emvl2(emvl2), state_wait_for_gpo_response{gpo_responder{this}}, state_wait_for_read{read_responder{this}} {};
    virtual bool start(uint8_t sw1, uint8_t sw2, const tlv_db fci, const candidate* candy, const issuer_script script, modulel2* l2) override {
        pr_debug("starting kernel3\n");
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

            kernel_db.insert(emvl2->l2_cfgs.terminal_cfg);
            kernel_db.update(combo->krn->db);
            kernel_db.update(combo->app->db);
            kernel_db.update(combo->transact->db);
            kernel_db.update(combo->db);
            kernel_db.insert(fci);

            // TTQ from preprocessing
            if (combo->indicator.ttq) {
                tlv_obj tlv(TTQ_9F66.id, *(combo->indicator.ttq));
                kernel_db.update(tlv);
                pr_debug("our TTQ from preprocessing: ", tlv.second, "\n");
                dump(TTQ_9F66, tlv.second);
            }
            // PDOL availability should have been checked by entry point
            auto& dol = fci[PDOL_9F38];
            secure_vector tags{};
            secure_vector missing{};
            build_dol(PDOL_9F38.id, dol, kernel_db, tags, missing);
            tags = make_tlv(0x83, tags);
            emvl2->set_state(&state_wait_for_gpo_response);
            emvl2->send_apdu(apdu_builder::build(COMMANDS::GPO).data(tags).le(0).to_bytes());
        }
        return true;
    }

    bool operator()(uint32_t tag, secure_vector::const_iterator begin,
                    secure_vector::const_iterator end, bool combined) {
        //logger.debug("TAG : ", to_hex(tag), "\n");
        if (!combined) {
            // 5.4.2.2
            if (kernel_db.has_tag(tag)) {
                logger.error("duplicated tlv found from card ", to_hex(tag));
                return false;
            };

            secure_vector v{begin, end};

            // A.2 Kernel 3
            if (tag == TRACK2_57.id && kernel_db.has_tag(PAN_5A)) {
                auto pan_5A = kernel_db(PAN_5A);
                auto pan_57 = TRACK2_57.get_pan(v);
                if (pan_57 != pan_5A) {
                    pr_debug("pan error: 57 does not match existing 5A\n");
                    return false;
                }
            } else if (tag == PAN_5A.id && kernel_db.has_tag(TRACK2_57)) {
                auto& _v = kernel_db[TRACK2_57];
                if (TRACK2_57.get_pan(_v) != PAN_5A.to_string(v)) {
                    pr_debug("pan error : 5A does not match existing 57\n");
                    return false;
                }
            }

            //4.1.1.1
            if (tag == FFI_9F6E.id) {
                v[3] &= 0xF0;
            };

            tlv_print(tag, v);
            if (!tlv_validate(tag, v)) {
                logger.error("tag ", to_hex(tag), " format error\n");
                return false;
            }

            tlv_obj obj{tag, std::move(v)};
            kernel_db.insert(std::move(obj));
        }
        return true;
    };

public:
    static constexpr std::array<const tag_info*, 14> mandatory_tags{
        // must be present in terminal
        &AMOUNT_AUTHORISED_9F02,
        &MERCHANT_NAME_AND_LOCATION_9F4E,
        &TRANSACTION_CURRENCY_CODE_5F2A,
        &TRANSACTION_DATE_9A,
        &TRANSACTION_TYPE_9C,
        &TERMINAL_COUNTRY_CODE_9F1A,
        &UNPREDICTABLE_NUMBER_9F37,

        // must be present in card
        &APPLICATION_CRYPTOGRAM_9F26,
        &AIP_82,
        &ATC_9F36,
        &DF_NAME_84,
        &ISSUER_APPLICATION_DATA_9F10,
        &TRACK2_57,
        &PDOL_9F38};

    void try_contact() {
        outcome o(OUTCOME_TYPE::TRY_ANOTHER_INTERFACE);
        o.start = RESTART_POINT::NA;
        o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
        o.cvm = OUTCOME_CVM::NA;
        o.ui_request = true;
        o.ui_request_data.ui_id = ui_message_id::INSERT_CARD;
        o.ui_request_data.status = ui_status_id::PROCESSING_ERR;
        o.ui_on_restart = false;
        o.data_record_present = false;
        o.discretionary_data_present = false;
        o.alt_interface = INTERFACE_TYPE::CONTACT;
        o.receipt = false;
        o.field_off_request = -1;
        o.removal_timeout = 0;
        emvl2->generate_outcome(o);
    };

    void insert_or_swipe() {
        outcome o(OUTCOME_TYPE::TRY_ANOTHER_INTERFACE);
        o.start = RESTART_POINT::NA;
        o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
        o.cvm = OUTCOME_CVM::NA;
        o.ui_request = true;
        o.ui_request_data.ui_id = ui_message_id::INSERT_OR_SWIPE;
        o.ui_request_data.status = ui_status_id::PROCESSING_ERR;
        o.ui_on_restart = false;
        o.data_record_present = false;
        o.discretionary_data_present = false;
        o.alt_interface = INTERFACE_TYPE::NA;
        o.receipt = false;
        o.field_off_request = -1;
        o.removal_timeout = 0;
        emvl2->generate_outcome(o);
    };

    void select_next() {
        outcome o(OUTCOME_TYPE::SELECT_NEXT);
        o.start = RESTART_POINT::C;
        o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
        o.cvm = OUTCOME_CVM::NA;
        o.ui_request = false;
        o.ui_on_restart = false;
        o.data_record_present = false;
        o.discretionary_data_present = false;
        o.alt_interface = INTERFACE_TYPE::NA;
        o.receipt = false;
        o.field_off_request = -1;
        o.removal_timeout = 0;
        emvl2->generate_outcome(o);
    };

    void try_again() {
        outcome o(OUTCOME_TYPE::TRY_AGAIN);
        o.start = RESTART_POINT::B;
        o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
        o.cvm = OUTCOME_CVM::NA;
        o.ui_request = true;
        o.ui_request_data.ui_id = ui_message_id::CHECK_PHONE;
        o.ui_request_data.status = ui_status_id::PROCESSING_ERR;
        o.ui_request_data.hold_time = 13;
        o.ui_on_restart = true;
        o.ui_restart_data.status = ui_status_id::PRESENT_CARD;
        o.data_record_present = false;
        o.discretionary_data_present = false;
        o.alt_interface = INTERFACE_TYPE::NA;
        o.receipt = false;
        o.field_off_request = 13;
        o.removal_timeout = 0;
        emvl2->generate_outcome(o);
    };

    void end_application() {
        outcome o(OUTCOME_TYPE::END_APPLICATION);
        o.start = RESTART_POINT::NA;
        o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
        o.cvm = OUTCOME_CVM::NA;
        o.ui_request = true;
        o.ui_request_data.ui_id = ui_message_id::INSERT_SWIPE_TRY_ANOTHER;
        o.ui_request_data.status = ui_status_id::PROCESSING_ERR;
        o.ui_on_restart = false;
        o.data_record_present = false;
        o.discretionary_data_present = false;
        o.alt_interface = INTERFACE_TYPE::NA;
        o.receipt = false;
        o.field_off_request = -1;
        o.removal_timeout = 0;
        emvl2->generate_outcome(o);
    };

    void read_card() {
        const uint8_t* next = state_wait_for_read.next;
        uint8_t sfi = AFL_94.get_sfi(next);
        emvl2->set_state(&state_wait_for_read);
        emvl2->send_apdu(apdu_builder::build(COMMANDS::READ_RECORD).p1(state_wait_for_read.next_record).p2((sfi << 3) | 4).le(0).to_bytes());
    };

    bool check_mandatory() {
        // 5.4.2.1
        for (auto p : mandatory_tags) {
            if (!kernel_db.has_tag(*p)) {
                pr_debug(p->desc, " <", to_hex(p->id), "> is missing\n");
                return false;
            }
        };

        auto transact_type = kernel_db(TRANSACTION_TYPE_9C);
        if (transact_type == TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK && kernel_db.has_tag(AMOUNT_OTHER_9F03)) {
            pr_debug("missing Amount Other for cash tranaction\n");
            return false;
        }

        auto& aip = kernel_db[AIP_82];
        pr_debug("AIP from card: ", aip, "\n");
        dump(AIP_82, kernel_db[AIP_82]);
        auto& ttq = kernel_db[TTQ_9F66];
        pr_debug("TTQ for terminal: ", ttq, "\n");
        dump(TTQ_9F66, ttq);

        auto k3cfg = candy->combo->krn;
        if ((v_get_bit(aip, TAG_AIP_82::dda_supported) || v_get_bit(aip, TAG_AIP_82::sda_supported_for_online_auth)) &&
            v_get_bit(ttq, TAG_TTQ_9F66::offline_data_auth_for_online_authorization_supported) && k3cfg->fddaForOnlineSupported) {

            if (!kernel_db.has_tag(SDAD_9F4B) &&
                !kernel_db.has_tag(SIGNED_STATIC_APPLICATION_DATA_93)) {
                pr_debug("missing tag 9F4B and 93\n");
                return false;
            }

            if (v_get_bit(aip, TAG_AIP_82::dda_supported) &&
                (!kernel_db.has_tag(SDAD_9F4B) ||
                 !kernel_db.has_tag(CA_PUBLIC_KEY_INDEX_8F) ||
                 emvl2->find_ca_key(get_rid(), kernel_db(CA_PUBLIC_KEY_INDEX_8F)) == nullptr ||
                 !kernel_db.has_tag(ISSUER_PUB_KEY_CERT_90) ||
                 !kernel_db.has_tag(ISSUER_PUB_KEY_EXP_9F32) ||
                 !kernel_db.has_tag(ISSUER_PUB_KEY_REMAINER_92) ||
                 !kernel_db.has_tag(ICC_PUB_KEY_CERT_9F46) ||
                 !kernel_db.has_tag(ICC_PUB_KEY_EXP_9F47) ||
                 !kernel_db.has_tag(KERNEL3::CARD_AUTH_RELATED_DATA_9F69) ||
                 !kernel_db.has_tag(PAN_5A))) {
                pr_debug("missing tag needed for DDA\n");
                return false;
            }

            if (v_get_bit(aip, TAG_AIP_82::sda_supported_for_online_auth) &&
                (!kernel_db.has_tag(SIGNED_STATIC_APPLICATION_DATA_93) ||
                 !kernel_db.has_tag(CA_PUBLIC_KEY_INDEX_8F) ||
                 emvl2->find_ca_key(get_rid(), kernel_db(CA_PUBLIC_KEY_INDEX_8F)) == nullptr ||
                 !kernel_db.has_tag(ISSUER_PUB_KEY_CERT_90) ||
                 !kernel_db.has_tag(ISSUER_PUB_KEY_EXP_9F32) ||
                 !kernel_db.has_tag(ISSUER_PUB_KEY_REMAINER_92) ||
                 !kernel_db.has_tag(PAN_5A))) {
                pr_debug("missing needed tag for SDA \n");
                return false;
            }
        };

        return true;
    };

    void complete_read() {
        pr_debug("\n\n... card read completed ...\n");
        if (kernel_db.has_tag(CTQ_9F6C)) {
            pr_debug("CTQ from card:\n");
            dump(CTQ_9F6C, kernel_db[CTQ_9F6C]);
        }

        struct ui_req_data ui {};
        ui.ui_id = ui_message_id::READ_OK;
        ui.status = ui_status_id::CARD_READ_OK;
        send_ui_event(ui);

        if (!check_mandatory()) {
            end_application();
            return;
        }

        // 5.4.3.1
        if (!kernel_db.has_tag(CID_9F27)) {
            secure_vector v(CID_9F27.maxlen);
            CID_9F27.set_type(v, kernel_db(ISSUER_APPLICATION_DATA_9F10));
            kernel_db.emplace(CID_9F27.id, std::move(v));
        };

        //5.4.3.2
        auto type = kernel_db(CID_9F27);
        switch (type) {
        case AC_TYPE::AAC:
            pr_debug("Got ACC from card\n");
            kernel_db.decline_required_by_reader = true;
            break;
        case AC_TYPE::ARQC:
            pr_debug("Got ARQC from card\n");
            kernel_db.online_required_by_reader = true;
            break;
        case AC_TYPE::TC:
            pr_debug("Got TC from card\n");
            if (kernel_db.get_bit(TTQ_9F66, TAG_TTQ_9F66::online_cryptogram_required)) {
                pr_debug("our TTQ rquires online cryptogram\n");
                kernel_db.online_required_by_reader = true;
            }
            break;
        default:
            pr_debug("unrecoginized cryptogram type\n");
            kernel_db.decline_required_by_reader = true;
        };

        if (!process_restriction())
            return;

        if (!process_offline_auth())
            return;

        OUTCOME_CVM cvm = OUTCOME_CVM::NA;

        if (!kernel_db.decline_required_by_reader) {
            cvm = process_cvm();
        };

        if (!kernel_db.decline_required_by_reader &&
            kernel_db.online_required_by_reader) {
            process_online(cvm);
        };

        if (!kernel_db.decline_required_by_reader &&
            !kernel_db.online_required_by_reader) {
            complete_offline(cvm);
        };

        if (kernel_db.decline_required_by_reader) {
            decline_transaction();
        };
    };

    void decline_transaction() {
        outcome o(OUTCOME_TYPE::DECLINED);
        o.start = RESTART_POINT::NA;
        o.cvm = OUTCOME_CVM::NO_CVM;
        o.ui_request = true;
        o.ui_request_data.ui_id = ui_message_id::NOT_AUTHORIZED;
        o.ui_on_restart = false;
        o.data_record_present = false;

        // 4.3.1.1
        if (kernel_db.has_tag(KERNEL3::AOSA_9F5D)) {
            // value qualifier, value, currency code 4.3.1.1
            auto& aosa = kernel_db[KERNEL3::AOSA_9F5D];
            o.ui_request_data.value_type = ui_value_id::BALANCE;
            o.ui_request_data.value = KERNEL3::AOSA_9F5D.to_string(aosa);
            o.ui_request_data.currency_code = TRANSACTION_CURRENCY_CODE_5F2A.to_string(kernel_db[TRANSACTION_CURRENCY_CODE_5F2A]);
            // Discretionary Data Present: see requirement 4.3.1.1
            o.discretionary_data_present = true;
            o.discretionary_data = make_tlv(KERNEL3::AOSA_9F5D.id, aosa);
        };
        o.alt_interface = INTERFACE_TYPE::NA;
        o.receipt = false;
        o.removal_timeout = 0;
        o.field_off_request = -1;
        emvl2->generate_outcome(o);
    };

    void complete_offline(OUTCOME_CVM cvm) {
        outcome o(OUTCOME_TYPE::APPROVED);
        o.start = RESTART_POINT::NA;
        o.cvm = cvm;
        o.ui_request = true;
        o.ui_request_data.ui_id = ui_message_id::APPROVED;
        o.data_record_present = true;
        prepare_emv_outcome_data(o.data_record);

        // 4.3.1.1
        if (kernel_db.has_tag(KERNEL3::AOSA_9F5D)) {
            // value qualifier, value, currency code 4.3.1.1
            auto& aosa = kernel_db[KERNEL3::AOSA_9F5D];
            o.ui_request_data.value_type = ui_value_id::BALANCE;
            o.ui_request_data.value = KERNEL3::AOSA_9F5D.to_string(aosa);
            o.ui_request_data.currency_code = TRANSACTION_CURRENCY_CODE_5F2A.to_string(kernel_db[TRANSACTION_CURRENCY_CODE_5F2A]);
            // Discretionary Data Present: see requirement 4.3.1.1
            o.discretionary_data_present = true;
            o.discretionary_data = make_tlv(KERNEL3::AOSA_9F5D.id, aosa);
        };
        o.alt_interface = INTERFACE_TYPE::NA;
        o.receipt = false;
        o.removal_timeout = 0;
        o.field_off_request = -1;

        emvl2->generate_outcome(o);
    };

    void process_online(OUTCOME_CVM cvm) {
        outcome o(OUTCOME_TYPE::ONLINE_REQUEST);
        o.cvm = cvm;
        o.ui_request = true;
        o.ui_request_data.ui_id = ui_message_id::AUTHORISING;

        // 4.3.1.1
        if (kernel_db.has_tag(KERNEL3::AOSA_9F5D)) {
            // value qualifier, value, currency code 4.3.1.1
            auto& aosa = kernel_db[KERNEL3::AOSA_9F5D];
            o.ui_request_data.value_type = ui_value_id::BALANCE;
            o.ui_request_data.value = KERNEL3::AOSA_9F5D.to_string(aosa);
            o.ui_request_data.currency_code = TRANSACTION_CURRENCY_CODE_5F2A.to_string(kernel_db[TRANSACTION_CURRENCY_CODE_5F2A]);
            // Discretionary Data Present: see requirement 4.3.1.1
            o.discretionary_data_present = true;
            o.discretionary_data = make_tlv(KERNEL3::AOSA_9F5D.id, aosa);
        };

        o.data_record_present = true;
        prepare_emv_outcome_data(o.data_record);

        o.alt_interface = INTERFACE_TYPE::NA;
        o.receipt = false;
        o.removal_timeout = 0;

        auto& ttq = kernel_db[TTQ_9F66];
        // 5.8.1.2
        if (v_get_bit(ttq, TAG_TTQ_9F66::issuer_update_processing_supported) &&
            kernel_db.has_tag(CTQ_9F6C) &&
            kernel_db.get_bit(CTQ_9F6C, TAG_CTQ_9F6C::card_support_issuer_update)) {
            o.start = RESTART_POINT::B;
            o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::EMV_DATA_AVAIL;
            o.ui_on_restart = true;
            o.ui_restart_data.ui_id = ui_message_id::TRY_AGAIN;
            o.field_off_request = 0;
        } else {
            o.start = RESTART_POINT::NA;
            o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
            o.ui_on_restart = false;
            o.field_off_request = -1;
        }

        emvl2->generate_outcome(o);
    };

    OUTCOME_CVM process_cvm() {
        // 5.7.1.1
        auto& ttq = kernel_db[TTQ_9F66];
        if (v_get_bit(ttq, TAG_TTQ_9F66::cvm_required) &&
            !kernel_db.has_tag(CTQ_9F6C)) {
            if (v_get_bit(ttq, TAG_TTQ_9F66::signature_supported)) {
                return OUTCOME_CVM::SIGNATURE;
            }

            if (v_get_bit(ttq, TAG_TTQ_9F66::online_pin_supported) &&
                v_get_bit(ttq, TAG_TTQ_9F66::consumer_device_cvm_supported)) {
                return OUTCOME_CVM::ONLINE_PIN;
            } else if (v_get_bit(ttq, TAG_TTQ_9F66::consumer_device_cvm_supported)) {
                kernel_db.decline_required_by_reader = true;
                return OUTCOME_CVM::NA;
            }
        }

        // 5.7.1.2
        if (kernel_db.has_tag(CTQ_9F6C)) {
            auto& ctq = kernel_db[CTQ_9F6C];
            if (v_get_bit(ctq, TAG_CTQ_9F6C::online_pin_required) &&
                v_get_bit(ttq, TAG_TTQ_9F66::online_pin_supported)) {
                kernel_db.online_required_by_reader = true;
                return OUTCOME_CVM::ONLINE_PIN;
            }

            if (v_get_bit(ctq, TAG_CTQ_9F6C::consumer_device_cmv_performed)) {
                if (kernel_db.has_tag(KERNEL3::CARD_AUTH_RELATED_DATA_9F69)) {
                    auto ctq_copy = KERNEL3::CARD_AUTH_RELATED_DATA_9F69.ctq(kernel_db[KERNEL3::CARD_AUTH_RELATED_DATA_9F69]);
                    if (ctq == ctq_copy) {
                        return OUTCOME_CVM::CONF_CODE_VERIFIED;
                    } else {
                        kernel_db.decline_required_by_reader = true;
                        return OUTCOME_CVM::NA;
                    }
                } else {
                    if (kernel_db(CID_9F27) == AC_TYPE::ARQC) {
                        return OUTCOME_CVM::CONF_CODE_VERIFIED;
                    } else {
                        kernel_db.decline_required_by_reader = true;
                        return OUTCOME_CVM::NA;
                    }
                }
            }

            if (v_get_bit(ctq, TAG_CTQ_9F6C::signature_required) &&
                v_get_bit(ttq, TAG_TTQ_9F66::signature_supported)) {
                return OUTCOME_CVM::SIGNATURE;
            }
        };

        // 5.7.1.3
        if (v_get_bit(ttq, TAG_TTQ_9F66::cvm_required)) {
            kernel_db.decline_required_by_reader = true;
        };

        return OUTCOME_CVM::NO_CVM;
    };

    bool process_offline_auth() {
        // 5.6.1.2
        if (!kernel_db.decline_required_by_reader && !kernel_db.online_required_by_reader) {
            pr_debug("perform offline authentication\n");
            if (!do_oda()) {
                if (kernel_db.has_tag(CTQ_9F6C)) {
                    auto& ctq = kernel_db[CTQ_9F6C];
                    if (v_get_bit(ctq, TAG_CTQ_9F6C::online_if_oda_fail_and_reader_online_capable)) {
                        if (kernel_db.has_tag(TTQ_9F66)) {
                            auto& ttq = kernel_db[TTQ_9F66];
                            if (!v_get_bit(ttq, TAG_TTQ_9F66::offline_only_reader)) {
                                kernel_db.online_required_by_reader = true;
                                return true;
                            }
                        }
                    }

                    if (v_get_bit(ctq, TAG_CTQ_9F6C::switch_intf_if_oda_fail_and_reader_support_contact)) {
                        if (kernel_db.has_tag(TTQ_9F66)) {
                            auto& ttq = kernel_db[TTQ_9F66];
                            if (!v_get_bit(ttq, TAG_TTQ_9F66::emv_contact_chip_supported)) {
                                try_contact();
                                return false;
                            }
                        }
                    }
                };

                kernel_db.decline_required_by_reader = true;
                return true;
            };
        } else {
            pr_debug("offline data auth not required\n");
        }
        return true;
    };

    bool do_oda() {
        if (!kernel_db.has_tag(CA_PUBLIC_KEY_INDEX_8F)) {
            pr_debug("missing tag 8F\n");
            return false;
        };

        auto cak = emvl2->find_ca_key(get_rid(), kernel_db(CA_PUBLIC_KEY_INDEX_8F));
        if (cak == nullptr) {
            pr_debug("sorry, missing ca key\n");
            return false;
        }

        if (kernel_db.has_tag(SDAD_9F4B)) {
            pr_debug("perform DDA\n");
            if (!kernel_db.has_tag(KERNEL3::CARD_AUTH_RELATED_DATA_9F69))
                return false;
            auto& v = kernel_db[KERNEL3::CARD_AUTH_RELATED_DATA_9F69];
            if (KERNEL3::CARD_AUTH_RELATED_DATA_9F69.fdda_version(v) != 0x01) {
                pr_debug("fdda version not 1\n");
                return false;
            }

            auto& sig = kernel_db[SDAD_9F4B];

            secure_vector ddol(kernel_db[UNPREDICTABLE_NUMBER_9F37]);

            auto& amount = kernel_db[AMOUNT_AUTHORISED_9F02];
            std::copy(amount.begin(), amount.end(), back_inserter(ddol));
            auto& currency_code = kernel_db[TRANSACTION_CURRENCY_CODE_5F2A];
            std::copy(currency_code.begin(), currency_code.end(), back_inserter(ddol));
            auto& card_auth_data = kernel_db[KERNEL3::CARD_AUTH_RELATED_DATA_9F69];
            std::copy(card_auth_data.begin(), card_auth_data.end(), back_inserter(ddol));
            return emvl2->verify_dda(kernel_db, cak, sig, kernel_db.static_oda_data, ddol);
        }

        if (kernel_db.has_tag(SIGNED_STATIC_APPLICATION_DATA_93)) {
            pr_debug("perform SDA\n");
            auto& sig = kernel_db[SIGNED_STATIC_APPLICATION_DATA_93];
            return emvl2->verify_sda(kernel_db, cak, sig, kernel_db.static_oda_data);
        }

        return false;
    };

    bool process_restriction() {
        pr_debug("process restriction\n");
        bool expired = false;

        // 5.5.1.1
        auto cid_type = kernel_db(CID_9F27);
        if (cid_type == AC_TYPE::TC) {
            if (kernel_db.has_tag(APPLICATION_EXPIRE_DATE_5F24)) {
                auto date = kernel_db(APPLICATION_EXPIRE_DATE_5F24);
                auto now = kernel_db(TRANSACTION_DATE_9A);
                pr_debug("Check card expire date ", date, " against now ", now, "\n");
                if (now > date) {
                    expired = true;
                }
            } else {
                pr_debug("no expire date found\n");
                expired = true;
            }

            if (expired) {
                pr_debug("application has expired\n");
                if (kernel_db.has_tag(CTQ_9F6C)) {
                    auto& v = kernel_db[CTQ_9F6C];
                    if (v_get_bit(v, TAG_CTQ_9F6C::online_if_application_expired)) {
                        pr_debug("CTQ requires online for app expire\n");
                        kernel_db.online_required_by_reader = true;
                    } else {
                        kernel_db.decline_required_by_reader = true;
                        return true;
                    }
                } else {
                    kernel_db.decline_required_by_reader = true;
                    return true;
                }
            };
        };

        //5.5.1.2
        auto k3cfg = candy->combo->krn;
        if (cid_type == AC_TYPE::TC && k3cfg->exceptionFileEnabled) {
            auto& v = kernel_db[TRACK2_57];
            auto pan = TRACK2_57.get_pan(v);
            if (emvl2->found_on_exceptions(pan)) {
                kernel_db.decline_required_by_reader = true;
                return true;
            };
        };

        // 5.5.1.3
        auto transact_type = kernel_db(TRANSACTION_TYPE_9C);
        if ((transact_type == TRANSACTION_TYPE::CASH || transact_type == TRANSACTION_TYPE::CASH_DISBURSEMENT) && k3cfg->aucManualCheckSupported) {
            bool allowed = false;
            if (kernel_db.has_tag(ISSUER_COUNTRY_CODE_5F28) && kernel_db.has_tag(AUC_9F07)) {
                auto icc = kernel_db(TERMINAL_COUNTRY_CODE_9F1A);
                auto tcc = kernel_db(ISSUER_COUNTRY_CODE_5F28);
                auto& auc = kernel_db[AUC_9F07];
                if ((icc == tcc && v_get_bit(auc, TAG_AUC_9F07::valid_for_domestic_cash)) ||
                    (icc != tcc && v_get_bit(auc, TAG_AUC_9F07::valid_for_international_cash))) {
                    allowed = true;
                }
            }

            if (!allowed) {
                if (kernel_db.has_tag(CTQ_9F6C)) {
                    auto& ctq = kernel_db[CTQ_9F6C];
                    if (v_get_bit(ctq, TAG_CTQ_9F6C::switch_intf_for_cash)) {
                        insert_or_swipe();
                        return false;
                    };
                }

                kernel_db.decline_required_by_reader = true;
                return true;
            }
        };

        //5.5.1.4
        if (transact_type == TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK && k3cfg->aucCashbackCheckSupported) {
            bool allowed = false;
            if (kernel_db.has_tag(ISSUER_COUNTRY_CODE_5F28) && kernel_db.has_tag(AUC_9F07)) {
                auto icc = kernel_db(TERMINAL_COUNTRY_CODE_9F1A);
                auto tcc = kernel_db(ISSUER_COUNTRY_CODE_5F28);
                auto& auc = kernel_db[AUC_9F07];
                if ((icc == tcc && v_get_bit(auc, TAG_AUC_9F07::domestic_cashback_allowed)) ||
                    (icc != tcc && v_get_bit(auc, TAG_AUC_9F07::international_cashback_allowed))) {
                    allowed = true;
                }
            }

            if (!allowed) {
                if (kernel_db.has_tag(CTQ_9F6C)) {
                    auto& ctq = kernel_db[CTQ_9F6C];
                    if (v_get_bit(ctq, TAG_CTQ_9F6C::switch_intf_for_cashback)) {
                        insert_or_swipe();
                        return false;
                    };
                }

                kernel_db.decline_required_by_reader = true;
                return true;
            }
        };

        return true;
    };

    secure_vector get_rid() {
        secure_vector rid{};
        auto& p = kernel_db[ADF_NAME_4F];
        std::copy(p.begin(), p.begin() + 5, back_inserter(rid));

        return rid;
    };

    void add_entry(secure_vector& records, uint32_t tag, secure_vector v) {
        auto tlv = make_tlv(tag, v);
        std::copy(tlv.begin(), tlv.end(), back_inserter(records));
    };

    void add_entry(secure_vector& records, const tag_info& tag) {
        if (kernel_db.has_tag(tag)) {
            auto& v = kernel_db[tag];
            add_entry(records, tag.id, v);
        } else {
            pr_debug("<", tag.desc, "> does not exist, ignore for records\n");
        };
    };

    void prepare_emv_outcome_data(secure_vector& records) {
        secure_vector data_records;
        add_entry(data_records, AMOUNT_AUTHORISED_9F02);
        if (kernel_db(TRANSACTION_TYPE_9C) == TRANSACTION_TYPE::PURCHASE_WITH_CASHBACK) {
            add_entry(data_records, AMOUNT_OTHER_9F03);
        };
        add_entry(data_records, APPLICATION_CRYPTOGRAM_9F26);
        add_entry(data_records, AIP_82);
        add_entry(data_records, ATC_9F36);
        add_entry(data_records, PAN_SEQ_5F34);
        add_entry(data_records, CUSTOMER_EXCLUSIVE_DATA_9F7C);
        add_entry(data_records, ISSUER_APPLICATION_DATA_9F10);
        add_entry(data_records, POS_ENTRY_MODE_9F39);
        add_entry(data_records, TERMINAL_COUNTRY_CODE_9F1A);
        add_entry(data_records, TERMINAL_CAPABILITIES_9F33);
        add_entry(data_records, TRACK2_57);
        add_entry(data_records, TRANSACTION_CURRENCY_CODE_5F2A);
        add_entry(data_records, TRANSACTION_DATE_9A);
        add_entry(data_records, TRANSACTION_TYPE_9C);
        add_entry(data_records, UNPREDICTABLE_NUMBER_9F37);

        secure_vector tvr(TVR_95.maxlen);
        add_entry(data_records, TVR_95.id, tvr);

        // 4.1.1.1
        if (kernel_db.has_tag(FFI_9F6E)) {
            auto v = kernel_db[FFI_9F6E];
            v[3] &= 0xF0;
            add_entry(data_records, FFI_9F6E.id, v);
        }

        records.swap(data_records);
    };

public:
    modulel2* emvl2;
    database kernel_db;
    const candidate* candy;

private:
    gpo_responder state_wait_for_gpo_response;
    read_responder state_wait_for_read;
};
}; // namespace emv::contactless

#endif

