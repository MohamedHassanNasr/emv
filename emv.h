/* emv.h - EVM Contactless, implementation in morden C++
 * Copyright 2019 Daniel Hu <daddy.of.qq@gmail.com>
 *
 * This file contains the Common code (like TLV, dda/cda, message/queue, etc.)  and Entry Point
 * Kernel 2 (Mastercard) and Kernel 3 (Visa) are implemented in separate files
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

#ifndef EMV_H
#define EMV_H

#include "message_and_id.h"

#include <algorithm>
#include <array>
#include <exception>
#include <functional>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>

namespace emv {

// disabling log at preprocessing time can save considerable space
#ifdef HAVE_LOG
#define pr_verbose(...) logger.verbose(__VA_ARGS__)
#define pr_debug(...) logger.debug(__VA_ARGS__)
#define pr_info(...) logger.info(__VA_ARGS__)
#define pr_warn(...) logger.warn(__VA_ARGS__)
#define pr_error(...) logger.error(__VA_ARGS__)
#else
#define pr_verbose(...)
#define pr_debug(...)
#define pr_info(...)
#define pr_warn(...)
#define pr_error(...)
#endif

void bignum_exp_modulus(const std::vector<uint8_t>& base,
                        const std::vector<uint8_t>& exponent,
                        const std::vector<uint8_t>& modulus,
                        std::vector<uint8_t>& result);
void compute_sha1(const uint8_t* data, size_t length, uint8_t* hash);

static constexpr std::array<uint8_t, 5> VISA_AID = {0xA0, 0x00, 0x00, 0x00, 0x03};

template <typename Dest, typename Src>
Dest narrow_cast(Src src) {
    Dest d = static_cast<Dest>(src);
    if (src != static_cast<Src>(d))
        throw std::bad_cast();

    return d;
};

static inline char nibble2hex(uint8_t b) {
    if (b <= 9) {
        return b + '0';
    } else {
        return b - 10 + 'A';
    }
};

static inline uint8_t hex2nibble(char h) {
    if (h >= '0' && h <= '9')
        return h - '0';

    if (h >= 'A' && h <= 'F')
        return h - 'A' + 10;

    return (h - 'a' + 10) & 0x0F;
};

static std::string to_decimal(uint32_t num, int digits = 0) {
    std::string ret{};
    while (num || digits) {
        char c = '0' + (num % 10);
        ret.push_back(c);
        num = num / 10;
        if (digits)
            digits--;
    }

    if (ret.size() == 0)
        ret = std::string{"0"};

    std::reverse(ret.begin(), ret.end());
    return ret;
};

static std::string to_decimal(const std::vector<uint8_t>& v) {
    uint32_t ret = 0;
    for (auto b : v) {
        ret = ((ret) << 8) + b;
    }

    return to_decimal(ret);
};

static std::vector<uint8_t> to_bcd(const std::vector<uint8_t>& bin) {
    uint32_t v = 0;
    for (auto b : bin) {
        v = ((v) << 8) + b;
    };

    std::vector<uint8_t> bcd{};
    while (v) {
        uint8_t d = v % 10;
        v = v / 10;
        d = d | ((v % 10) << 4);
        v = v / 10;
        bcd.push_back(d);
    };

    if (bcd.size() == 0)
        bcd.resize(1);

    std::reverse(bcd.begin(), bcd.end());

    return bcd;
};

static std::vector<uint8_t> hex2vector(const std::string& hex) {
    std::vector<uint8_t> v(hex.size() / 2);
    for (unsigned i = 0; i != v.size(); i++) {
        uint8_t b = hex2nibble(hex[i << 1]);
        b = (b << 4) | hex2nibble(hex[(i << 1) + 1]);
        v[i] = b;
    };
    return v;
};

static std::string vector2hex(const std::vector<uint8_t>& v) {
    std::string hex{};
    for (auto b : v) {
        hex.push_back(nibble2hex(b >> 4));
        hex.push_back(nibble2hex(b & 0x0F));
    }
    return hex;
};

// only useful for 4 bytes and below
static uint32_t vector2int(const std::vector<uint8_t>& v) {
    uint32_t r = 0;
    for (unsigned i = 0; i != v.size(); i++) {
        r = (r << 8) | v[i];
    }
    return r;
};

static inline std::string byte2hex(uint8_t b) {
    std::string str{};
    str.push_back(nibble2hex(b >> 4));
    str.push_back(nibble2hex(b & 0x0F));
    return str;
};

std::string to_hex(uint32_t i) {
    std::string hex;
    uint32_t mask = 0xFF000000;
    int shift = 24;

    while (mask != 0) {
        uint8_t b = (mask & i) >> shift;
        if (b || hex.size()) {
            hex += byte2hex(b);
        }
        mask >>= 8;
        shift -= 8;
    }

    if (hex.size() == 0)
        hex = "00";

    return hex;
};

class Logger {
public:
    enum class LEVEL : uint8_t {
        error,
        warn,
        info,
        debug,
        verbose
    };

    Logger(LEVEL l = LEVEL::debug) : level{l} {};

    template <typename... Args>
    void verbose(Args&&... args) {
        print(LEVEL::verbose, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void debug(Args&&... args) {
        print(LEVEL::debug, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void info(Args&&... args) {
        print(LEVEL::info, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void warn(Args&&... args) {
        print(LEVEL::warn, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void error(Args&&... args) {
        print(LEVEL::error, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void print(LEVEL l, Args&&... args) {
        if (level >= l)
            do_print(std::forward<Args>(args)...);
    };

private:
    void log(const std::string& msg);
    void log(const char* str);

    template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
    void log(T i) {
        log(std::to_string(i));
    }
    void log(const std::vector<uint8_t>& bytes) {
        log(vector2hex(bytes));
    };

    template <typename T, typename... Args>
    void do_print(T arg, Args&&... args) {
        log(arg);
        if constexpr (sizeof...(args) > 0) {
            do_print(std::forward<Args>(args)...);
        }
    };

    LEVEL level;
};

extern Logger logger;

Logger& operator<<(Logger& l, std::string msg) {
    l.info(msg);
    return l;
}

Logger& operator<<(Logger& l, int num) {
    l.info(num);
    return l;
}

Logger& operator<<(Logger& l, const std::vector<uint8_t>& bytes) {
    l.info(bytes);
    return l;
}

#define MAX_TAG_SIZE sizeof(uint32_t)

template <typename Iter>
bool tlv_get_tag(Iter& begin, Iter end, uint32_t& tag, uint8_t& tag_size) {
    if (begin == end)
        return false;

    tag_size = 1;
    tag = *begin++;

    if ((tag & 0x1F) == 0x1F) {
        do {
            if (begin == end || tag_size++ > MAX_TAG_SIZE)
                return false;
            tag = (tag << 8) + *begin++;
        } while (tag & 0x80);
    }

    return true;
}

template <typename Iter>
bool tlv_get_length(Iter& begin, Iter end, uint32_t& length) {
    if (begin >= end)
        return false;

    length = *begin++;
    if (length & 0x80) {
        unsigned num = length & 0x7f;
        length = 0;
        while (num-- > 0) {
            if (begin == end)
                return false;
            length = (length << 8) + *begin++;
        }
    }

    return true;
}

std::vector<uint8_t> tag_in_bytes(uint32_t tag) {
    std::vector<uint8_t> ret{};
    uint8_t shift = 24;
    uint32_t mask = 0xFF000000;
    while (mask != 0 && (tag & mask) == 0) {
        mask >>= 8;
        shift -= 8;
    }

    while (mask != 0) {
        uint8_t b = static_cast<uint8_t>((tag & mask) >> shift);
        ret.push_back(b);
        shift -= 8;
        mask >>= 8;
    };

    return ret;
};

std::vector<uint8_t> make_tlv(uint32_t tag, const std::vector<uint8_t>& value){
    std::vector<uint8_t> ret{};
    uint8_t shift = 24;
    uint32_t mask = 0xFF000000;
    while (mask != 0 && (tag & mask) == 0) {
        mask >>= 8;
        shift -= 8;
    }

    while (mask != 0) {
        uint8_t b = static_cast<uint8_t>((tag & mask) >> shift);
        ret.push_back(b);
        shift -= 8;
        mask >>= 8;
    };

    uint32_t size = value.size();
    if (size <= 0x7F) {
        ret.push_back(static_cast<uint8_t>(value.size()));
    } else {
        shift = 24;
        mask = 0xFF000000;
        while (mask != 0 && (size & mask) == 0) {
            mask >>= 8;
            shift -= 8;
        }
        uint8_t num = (shift >> 3) + 1;
        ret.push_back(static_cast<uint8_t>(0x80 | num));
        while (mask != 0) {
            ret.push_back(static_cast<uint8_t>((size & mask) >> shift));
            shift -= 8;
            mask >>= 8;
        }
    }

    std::copy(value.begin(), value.end(), back_inserter(ret));
    return ret;
};

template <typename Iter>
bool tlv_get(Iter begin, Iter& end, uint32_t& tag, uint8_t& tagSize, Iter& value) {
    uint32_t length;

    if (!tlv_get_tag(begin, end, tag, tagSize) ||
        !tlv_get_length(begin, end, length) ||
        begin + length > end)
        return false;

    value = begin;
    end = begin + length;
    return true;
}

static bool tag_is_constructed(uint32_t tag) {
    uint8_t shift = 24;
    uint32_t mask = 0xFF000000;

    while (mask != 0 && (tag & mask) == 0) {
        mask >>= 8;
        shift -= 8;
    }

    uint8_t b = static_cast<uint8_t>((tag & mask) >> shift);
    return ((b & 0x20) != 0);
};

static inline bool tag_is_primitive(uint32_t tag) {
    return !tag_is_constructed(tag);
};

template <typename Iter, typename Visitor>
bool tlv_visit(Iter begin, Iter end, Visitor& v, bool recurse = true) {
    uint32_t tag = 0;
    uint8_t tagSize = 0;
    Iter value;

    while (begin < end) {
        Iter _end = end;
        if (*begin == 0x00) {
            begin++;
            continue;
        }

        if (!tlv_get(begin, _end, tag, tagSize, value))
            return false;

        // constructed or primitive type?
        if (((tag >> ((tagSize - 1) * 8)) & 0x20) != 0) {
            if (!v(tag, value, _end, true)) {
                return false;
            };
            if (recurse && !tlv_visit(value, _end, v, recurse))
                return false;
        } else {
            if (!v(tag, value, _end, false))
                return false;
        }

        begin = _end;
    }

    return true;
}

enum class TAG_TYPE : uint8_t {
    A,
    AN,
    ANS,
    B,
    N,
    CN,
    VAR
};

using TAG_PERM = uint8_t;

static constexpr uint8_t PERM_ACT = 0x01;
static constexpr uint8_t PERM_DET = 0x02;
static constexpr uint8_t PERM_RA = 0x04;
static constexpr uint8_t PERM_K = 0x08;

struct tag_info {
    constexpr tag_info(uint32_t id, TAG_TYPE type, const char* desc, uint8_t minlen, uint8_t maxlen, TAG_PERM perm = PERM_K) : id{id}, type{type}, desc{desc}, minlen{minlen}, maxlen{maxlen}, perm{perm} {};
    uint32_t id;
    TAG_TYPE type;
    const char* desc;
    uint8_t minlen;
    uint8_t maxlen;
    TAG_PERM perm;

    virtual bool validate(const std::vector<uint8_t>& value) const {
        return value.size() >= minlen && value.size() <= maxlen;
    };
    virtual std::vector<uint8_t> DOL(const std::vector<uint8_t>& value, size_t length) const {
        std::vector<uint8_t> ret(value);
        ret.resize(length);
        return ret;
    }

    virtual std::string to_string(const std::vector<uint8_t>& v) const {
        std::string ret{};
        for (auto b : v) {
            ret.push_back(nibble2hex(b >> 4));
            ret.push_back(nibble2hex(b & 0x0F));
        };
        return ret;
    };

    bool has_permission(TAG_PERM permission) const {
        return (perm & permission) != permission;
    };
};

struct tag_hash {
    size_t operator()(const tag_info* t) const {
        return std::hash<uint32_t>()(t->id);
    }
};

struct tag_eq {
    bool operator()(const tag_info* t1, const tag_info* t2) const {
        return t1->id == t2->id;
    };
};

using tag_sets = std::unordered_set<const tag_info*, tag_hash, tag_eq>;

struct tag_ans : tag_info {
    constexpr tag_ans(int id, const char* desc, uint8_t minlen, uint8_t maxlen, TAG_PERM perm = PERM_K) : tag_info(id, TAG_TYPE::ANS, desc, minlen, maxlen, perm){};

    virtual std::string to_string(const std::vector<uint8_t>& value) const override {
        std::string ret{};
        for (auto b : value) {
            ret.push_back(static_cast<char>(b));
        }
        return ret;
    };
};

struct tag_an : tag_info {
    constexpr tag_an(int id, const char* desc, uint8_t minlen, uint8_t maxlen, TAG_PERM perm = PERM_K) : tag_info(id, TAG_TYPE::ANS, desc, minlen, maxlen, perm){};

    virtual std::string to_string(const std::vector<uint8_t>& value) const override {
        std::string ret{};
        for (auto b : value) {
            ret.push_back(static_cast<std::string::value_type>(b));
        }
        return ret;
    };
};

using numeric_value_type = uint32_t;
struct tag_n : tag_info {
    constexpr tag_n(uint32_t id, const char* desc, uint8_t minlen, uint8_t maxlen, TAG_PERM perm = PERM_K) : tag_info{id, TAG_TYPE::N, desc, minlen, maxlen, perm} {};

    // ignore leading '0'
    std::string to_string(const std::vector<uint8_t>& v) const override {
        auto ret = std::string{};
        bool ignore_zero = true;

        for (auto b : v) {
            auto n = b >> 4;

            if (n > 9)
                break;
            if (n != 0 || !ignore_zero) {
                ret.push_back('0' + n);
                ignore_zero = false;
            }

            n = b & 0x0F;
            if (n > 9)
                break;
            if (n != 0 || !ignore_zero) {
                ret.push_back('0' + n);
                ignore_zero = false;
            }
        }
        return ret;
    }

    std::vector<uint8_t> from_string(const std::string& s) const {
        int size = (maxlen + 1) / 2;
        std::vector<uint8_t> ret(size);
        auto p = s.rbegin();
        while (p != s.rend() && size-- > 0) {
            uint8_t b = ((*p - '0') & 0x0F);
            p++;
            if (p != s.rend()) {
                b |= ((*p - '0') & 0x0F) << 4;
                p++;
            }
            ret[size] = b;
        }
        return ret;
    }

    virtual std::vector<uint8_t> DOL(const std::vector<uint8_t>& value, size_t length) const override {
        std::vector<uint8_t> ret{};
        if (value.size() > length) { // leftmost truncated
            std::copy(value.begin() + (value.size() - length), value.end(), back_inserter(ret));
            return ret;
        } else { // leftmost padding
            ret.resize(length - value.size());
            std::copy(value.begin(), value.end(), back_inserter(ret));
        }
        return ret;
    };

    static bool is_numeric(unsigned char b) {
        return b >= 0 && b <= 9;
    }

    static numeric_value_type to_numeric_value(const std::vector<uint8_t>& v) {
        numeric_value_type ret = 0;
        for (auto b : v) {
            ret = 10 * ret + ((b >> 4) & 0x0F);
            ret = 10 * ret + (b & 0x0F);
        }
        return ret;
    }

    virtual bool validate(const std::vector<uint8_t>& v) const override {
        if (v.size() > static_cast<unsigned int>((maxlen + 1) / 2) ||
            v.size() < static_cast<unsigned int>((minlen + 1) / 2))
            return false;

        // TODO check nlen other than full length
        for (auto b : v) {
            if (!is_numeric(b >> 4) || !is_numeric(b & 0x0F))
                return false;
        }
        return true;
    }
};

struct tag_date : tag_n {
    constexpr tag_date(uint32_t id, const char* desc, TAG_PERM perm = PERM_K) : tag_n(id, desc, 6, 6, perm){};
    std::string to_string(const std::vector<uint8_t>& v) const override {
        return vector2hex(v);
    }
};

struct tag_cn : tag_info {
    constexpr tag_cn(uint32_t id, const char* desc, uint8_t minlen, uint8_t maxlen, TAG_PERM perm = PERM_K) : tag_info{id, TAG_TYPE::CN, desc, minlen, maxlen, perm} {};

    // ignore trailing padding 'F' or whatever
    std::string to_string(const std::vector<uint8_t>& v) const override {
        auto ret = std::string{};
        for (auto b : v) {
            auto n = b >> 4;
            if (n <= 9)
                ret.push_back('0' + n);
            else
                break;
            n = b & 0x0F;
            if (n <= 9)
                ret.push_back('0' + n);
            else
                break;
        }
        return ret;
    }

    std::vector<uint8_t> from_string(const std::string& d) {
        return std::vector<uint8_t>();
    }

    virtual std::vector<uint8_t> DOL(const std::vector<uint8_t>& value, size_t length) const override {
        std::vector<uint8_t> ret(value);
        if (value.size() < length) {
            for (unsigned i = 0; i != length - value.size(); i++) {
                ret.push_back(0xFF);
            }
            return ret;
        } else {
            ret.resize(length);
        };

        return ret;
    };

    bool validate(const std::vector<uint8_t>& v) const override {
        if (v.size() < minlen || v.size() > maxlen) {
            return false;
        };

        // TODO check CN format
        return true;
    };
};

struct tag_b : tag_info {
    constexpr tag_b(uint32_t id, const char* desc, uint8_t minlen, uint8_t maxlen, TAG_PERM perm = PERM_K) : tag_info{id, TAG_TYPE::B, desc, minlen, maxlen, perm} {};
};

struct tag_var : tag_info {
    constexpr tag_var(uint32_t id, const char* desc, uint8_t minlen, uint8_t maxlen, TAG_PERM perm = PERM_K) : tag_info{id, TAG_TYPE::VAR, desc, minlen, maxlen, perm} {};
};

struct tag_bit_field {
    unsigned char byte;
    unsigned char bit;
    const char* desc;
};

void v_set_bit(std::vector<uint8_t>& value, const tag_bit_field& pos) {
    value[pos.byte - 1] |= (0x01 << (pos.bit - 1));
};

void v_clear_bit(std::vector<uint8_t>& value, const tag_bit_field& pos) {
    value[pos.byte - 1] &= ~(0x01 << (pos.bit - 1));
};

int v_get_bit(std::vector<uint8_t> const& value, const tag_bit_field& pos) {
    return value[pos.byte - 1] & (0x01 << (pos.bit - 1));
};

#define DECL_TAG_BIT(name, p1, p2) \
    static constexpr tag_bit_field name = {p1, p2, #name}

static void dump(const std::vector<uint8_t>& v, const tag_bit_field* field) {
    if ((v[field->byte - 1] & (0x01 << (field->bit - 1))) != 0) {
        pr_debug("<", field->desc, "> ");
    }
};

template <typename TAG>
static void dump(TAG& tag, const std::vector<uint8_t>& v) {
    for (auto p : tag.all_bits) {
        dump(v, p);
    }
    pr_debug("\n");
};

// called from inside TAG static definition
#define DUMP(v)                    \
    do {                           \
        for (auto _x : all_bits) { \
            dump((v), _x);         \
        }                          \
    } while (false);

#define DECL_TAG_N(name, desc, tag, MIN, MAX, ...)                                   \
    static constexpr char name##_desc[] = desc;                                      \
    struct TAG_##name : public tag_n {                                               \
        constexpr TAG_##name() : tag_n(tag, name##_desc, MIN, MAX, ##__VA_ARGS__){}; \
    };                                                                               \
    static constexpr TAG_##name name{};

#define DECL_TAG_DATE(name, desc, tag, ...)                                   \
    static constexpr char name##_desc[] = desc;                               \
    struct TAG_##name : public tag_date {                                     \
        constexpr TAG_##name() : tag_date(tag, name##_desc, ##__VA_ARGS__){}; \
    };                                                                        \
    static constexpr TAG_##name name{};

#define DECL_TAG_CN(name, desc, tag, MIN, MAX, ...)                                   \
    static constexpr char name##_desc[] = desc;                                       \
    struct TAG_##name : public tag_cn {                                               \
        constexpr TAG_##name() : tag_cn(tag, name##_desc, MIN, MAX, ##__VA_ARGS__){}; \
    };                                                                                \
    static constexpr TAG_##name name{};

#define DECL_TAG_B(name, desc, tag, MIN, MAX, ...)                                   \
    static constexpr char name##_desc[] = desc;                                      \
    struct TAG_##name : public tag_b {                                               \
        constexpr TAG_##name() : tag_b(tag, name##_desc, MIN, MAX, ##__VA_ARGS__){}; \
    };                                                                               \
    static constexpr TAG_##name name{};

#define DECL_TAG_VAR(name, desc, tag, MIN, MAX, ...)                                   \
    static constexpr char name##_desc[] = desc;                                        \
    struct TAG_##name : public tag_var {                                               \
        constexpr TAG_##name() : tag_var(tag, name##_desc, MIN, MAX, ##__VA_ARGS__){}; \
    };                                                                                 \
    static constexpr TAG_##name name{};

#define DECL_TAG_ANS(name, desc, tag, MIN, MAX, ...)                                   \
    static constexpr char name##_desc[] = desc;                                        \
    struct TAG_##name : public tag_ans {                                               \
        constexpr TAG_##name() : tag_ans(tag, name##_desc, MIN, MAX, ##__VA_ARGS__){}; \
    };                                                                                 \
    static constexpr TAG_##name name{};

#define DECL_TAG_AN(name, desc, tag, MIN, MAX, ...)                                   \
    static constexpr char name##_desc[] = desc;                                       \
    struct TAG_##name : public tag_an {                                               \
        constexpr TAG_##name() : tag_an(tag, name##_desc, MIN, MAX, ##__VA_ARGS__){}; \
    };                                                                                \
    static constexpr TAG_##name name{};

static std::string to_string(OUTCOME_CVM cvm) {
    switch (cvm) {
    case OUTCOME_CVM::NO_CVM:
        return std::string("NO_CVM");
    case OUTCOME_CVM::SIGNATURE:
        return std::string("SIGNATURE");
    case OUTCOME_CVM::ONLINE_PIN:
        return std::string("ONLINE_PIN");
    case OUTCOME_CVM::CONF_CODE_VERIFIED:
        return std::string("CONF_CODE_VERIFIED");
    default:
        break;
    };

    return std::string{};
};

enum class RESTART_POINT : uint8_t {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    NA = 0x0F
};

static std::string to_string(RESTART_POINT start) {
    switch (start) {
    case RESTART_POINT::A:
        return std::string("A");
    case RESTART_POINT::B:
        return std::string("B");
    case RESTART_POINT::C:
        return std::string("C");
    case RESTART_POINT::D:
        return std::string("D");
    default:
        break;
    }
    return std::string{};
};

enum class OUTCOME_TYPE : uint8_t {
    APPROVED = 1,
    DECLINED = 2,
    ONLINE_REQUEST = 3,
    END_APPLICATION = 4,
    SELECT_NEXT = 5,
    TRY_ANOTHER_INTERFACE = 6,
    TRY_AGAIN = 7,
    NA = 15
};

static std::string to_string(OUTCOME_TYPE outcome_type) {
    switch (outcome_type) {
    case OUTCOME_TYPE::APPROVED:
        return std::string("APPROVED");
    case OUTCOME_TYPE::DECLINED:
        return std::string("DECLINED");
    case OUTCOME_TYPE::ONLINE_REQUEST:
        return std::string("ONLINE REQUEST");
    case OUTCOME_TYPE::END_APPLICATION:
        return std::string("END APPLICATION");
    case OUTCOME_TYPE::SELECT_NEXT:
        return std::string("SELECT NEXT");
    case OUTCOME_TYPE::TRY_ANOTHER_INTERFACE:
        return std::string("TRY ANOTHER INTERFACE");
    case OUTCOME_TYPE::TRY_AGAIN:
        return std::string("TRY AGAIN");
    default:
        break;
    }

    return std::string{};
};

struct ui_req_data {
    ui_req_data() : hold_time(0) {
        value_type = ui_value_id::NA;
    }

    ui_message_id ui_id;
    ui_status_id status;
    int hold_time;
    std::string lang;
    ui_value_id value_type;
    std::string value;
    std::string currency_code;
};

std::string to_string(ui_value_id id) {
    switch (id) {
    case ui_value_id::AMOUNT:
        return std::string("AMOUNT");
    case ui_value_id::BALANCE:
        return std::string("BALANCE");
    default:
        break;
    }

    return std::string{};
};

std::string to_string(ui_message_id id) {
    switch (id) {
    case ui_message_id::APPROVED:
        return std::string("Approved");
    case ui_message_id::NOT_AUTHORIZED:
        return std::string("Not Authorised");
    case ui_message_id::ENTER_PIN:
        return std::string("Please enter your PIN");
    case ui_message_id::PROCESSING_ERR:
        return std::string("Processing error");
    case ui_message_id::REMOVE_CARD:
        return std::string("Please remove card");
    case ui_message_id::WELCOME:
        return std::string("Welcome");
    case ui_message_id::PRESENT_CARD:
        return std::string("Present card");
    case ui_message_id::PROCESSING:
        return std::string("Processing");
    case ui_message_id::READ_OK:
        return std::string("Card read OK, Please remove card");
    case ui_message_id::INSERT_OR_SWIPE:
        return std::string("Please insert or swipe card");
    case ui_message_id::PRESENT_ONE_ONLY:
        return std::string("Please present one card only");
    case ui_message_id::APPROVED_PLEASE_SIGN:
        return std::string("Approved Please sign");
    case ui_message_id::AUTHORISING:
        return std::string("Authorising Please Wait");
    case ui_message_id::INSERT_SWIPE_TRY_ANOTHER:
        return std::string("Insert, swipe or try another card");
    case ui_message_id::INSERT_CARD:
        return std::string("Please insert card");
    case ui_message_id::NO_MESSAGE:
        return std::string("*** CLEAR ****");
    case ui_message_id::CHECK_PHONE:
        return std::string("See Phone for Instructions");
    case ui_message_id::TRY_AGAIN:
        return std::string("Present card again");
    default:
        break;
    }
    return std::string();
};

std::string to_string(ui_status_id id) {
    switch (id) {
    case ui_status_id::NOT_READY:
        return std::string("Not Ready");
    case ui_status_id::IDLE:
        return std::string("Idle");
    case ui_status_id::PRESENT_CARD:
        return std::string("Ready to Read (Present Card)");
    case ui_status_id::PROCESSING:
        return std::string("Processing");
    case ui_status_id::CARD_READ_OK:
        return std::string("Card Read Successfully (Remove Card)");
    case ui_status_id::PROCESSING_ERR:
        return std::string("Processing Error");
    case ui_status_id::CONTACTLESS_NOT_SATISFIED:
        return std::string("Processing Error: Conditions for use of contactless not satisfied");
    case ui_status_id::COLLISION_ERR:
        return std::string("Processing Error: Contactless collision detected");
    case ui_status_id::CARD_NOT_REMOVED:
        return std::string("Card not removed from reader");
    default:
        break;
    }

    return std::string();
};

enum class OUTCOME_KERNEL_RESTART_COND : uint8_t {
    EMV_DATA_AVAIL,
    ANY,
    NA
};

enum class L1_ERROR : uint8_t {
    OK = 0x00,
    TIME_OUT_ERROR = 0x01,
    TRANSMISSION_ERROR = 0x02,
    PROTOCOL_ERROR = 0x03
};

enum class L2_ERROR : uint8_t {
    OK = 0x00,
    CARD_DATA_MISSING = 0x01,
    CAM_FAILED = 0x02,
    STATUS_BYTES = 0x03,
    PARSING_ERROR = 0x04,
    MAX_LIMIT_EXCEEDED = 0x05,
    CARD_DATA_ERROR = 0x06,
    MS_NOT_SUPPORTED = 0x07,
    NO_PPSE = 0x08,
    PPSE_FAULT = 0x09,
    EMPTY_CANDIDATE_LIST = 0x0A,
    IDS_READ_ERROR = 0x0B,
    IDS_WRITE_ERROR = 0x0C,
    IDS_DATA_ERROR = 0x0D,
    IDS_NO_MATCHING_AC = 0x0E,
    TERMINAL_DATA_ERROR = 0x0F
};

enum class L3_ERROR : uint8_t {
    OK = 0x00,
    TIME_OUT = 0x01,
    STOP = 0x02,
    AMOUNT_NOT_PRESENT = 0x03
};

enum class INTERFACE_TYPE : uint8_t {
    CONTACT,
    CONTACTLESS,
    MAGSTRIPE,
    NA
};

struct outcome {
    outcome(OUTCOME_TYPE type) : type{type} {
        kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
        start = RESTART_POINT::NA;
        alt_interface = INTERFACE_TYPE::NA;
        receipt = false;
        ui_request = false;
        ui_on_restart = false;
        data_record_present = false;
        discretionary_data_present = false;
        field_off_request = -1;
        removal_timeout = 0;
        cvm = OUTCOME_CVM::NA;
    };

    OUTCOME_TYPE type;
    RESTART_POINT start;
    OUTCOME_KERNEL_RESTART_COND kernel_restart_cond;
    OUTCOME_CVM cvm;
    bool ui_request;
    ui_req_data ui_request_data;
    bool ui_on_restart;
    ui_req_data ui_restart_data;
    bool data_record_present;
    std::vector<uint8_t> data_record;
    bool discretionary_data_present;
    std::vector<uint8_t> discretionary_data;
    INTERFACE_TYPE alt_interface;
    bool receipt;
    int field_off_request;
    int removal_timeout;
};

DECL_TAG_N(PAN_SEQ_5F34, "Application Primary Account Number (PAN) Sequence Number", 0x5F34, 2, 2,
           PERM_K | PERM_RA);
DECL_TAG_N(POS_ENTRY_MODE_9F39, "Point-of-Service (POS) Entry Mode", 0x9F39, 2, 2);
DECL_TAG_N(TERMINAL_COUNTRY_CODE_9F1A, "Terminal Country Code", 0x9F1A, 3, 3);
DECL_TAG_N(ISSUER_COUNTRY_CODE_5F28, "Issuer Country Code", 0x5F28, 3, 3,
           PERM_K | PERM_RA);
DECL_TAG_DATE(APPLICATION_EXPIRE_DATE_5F24, "Application Expiration Date", 0x5F24);
DECL_TAG_DATE(TRANSACTION_DATE_9A, "Transaction Date", 0x9A, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_DATE(TRANSACTION_TIME_9F21, "Transaction Time", 0x9F21, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_N(ISSUER_CODE_TABLE_INDEX_9F11, "Issuer Code Table Index", 0x9F11, 2, 2,
           PERM_K | PERM_RA);
DECL_TAG_N(TRANSACTION_CURRENCY_CODE_5F2A, "Transaction Currency Code", 0x5F2A, 3, 3, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_N(TRANSACTION_CURRENCY_EXPONENT_5F36, "Transaction Currency Exponent", 0x5F36, 1, 1, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_N(AMOUNT_OTHER_9F03, "Amount, Other (Numeric)", 0x9F03, 12, 12, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_N(ACCOUNT_TYPE_5F57, "Account Type", 0x5F57, 2, 2, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_N(ACQUIRER_IDENTIFIER_9F01, "Acquirer Identifier", 0x9F01, 6, 11);
DECL_TAG_N(APPLICATION_CURRENCY_CODE_9F42, "Application Currency Code", 0x9F42, 3, 3,
           PERM_K | PERM_RA);
DECL_TAG_N(APPLICATION_CURRENCY_EXPONENT_9F44, "Application Currency Exponent", 0x9F44, 1, 1,
           PERM_K | PERM_RA);
DECL_TAG_DATE(APPLICATION_EFFECTIVE_DATE_5F25, "Application Effective Date", 0x5F25,
              PERM_K | PERM_RA);
DECL_TAG_DATE(APPLICATION_EXPIRATION_DATE_5F24, "Application Expiration Date", 0x5F24,
              PERM_K | PERM_RA);
DECL_TAG_N(BALANCE_READ_BEFORE_GEN_AC_DF8104, "Balance Read Before Gen AC", 0xDF8104, 12, 12,
           PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_N(BALANCE_READ_AFTER_GEN_AC_DF8105, "Balance Read After Gen AC", 0xDF8105, 12, 12,
           PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_N(DS_ID_9F5E, "DS ID", 0x9F5E, 8, 11, PERM_K | PERM_RA);
DECL_TAG_N(MERCHANT_CATEGORY_CODE_9F15, "Merchant Category Code", 0x9F15, 4, 4);
DECL_TAG_N(MESSAGE_HOLD_TIME_DF812D, "Message Hold Time", 0xDF812D, 6, 6);
DECL_TAG_N(OFFLINE_ACCUMULATOR_BALANCE_9F50, "Offline Accumulator Balance", 0x9F50, 12, 12, PERM_K | PERM_RA);
DECL_TAG_N(READER_CONTACTLESS_FLOOR_LIMIT_DF8123, "Reader Contactless Floor Limit", 0xDF8123, 12, 12);
DECL_TAG_N(READER_CONTACTLESS_TRANSACTION_LIMIT_NO_ON_DEVICE_CVM_DF8124, "Reader Contactless Transaction Limit (No On-device CVM)", 0xDF8124, 12, 12);
DECL_TAG_N(READER_CONTACTLESS_TRANSACTION_LIMIT_ON_DEVICE_CVM_DF8125, "Reader Contactless Transaction Limit (On-device CVM)", 0xDF8125, 12, 12);
DECL_TAG_N(READER_CVM_REQUIRED_LIMIT_DF8126, "Reader CVM Required Limit", 0xDF8126, 12, 12);
DECL_TAG_N(SERVICE_CODE_5F30, "Service Code", 0x5F30, 3, 3, PERM_K | PERM_RA);

DECL_TAG_N(UNPREDICTABLE_NUMBER_NUMERIC_9F6A, "Unpredictable Number (Numeric)", 0x9F6A, 8, 8);

DECL_TAG_CN(PAN_5A, "Application Primary Account Number (PAN)", 0x5A, 0, 19,
            PERM_K | PERM_RA);
DECL_TAG_CN(DD_CARD_TRACK2_DF812B, "DD Card (Track2)", 0xDF812B, 0, 11);
DECL_TAG_CN(TRACK2_DISCRETIONARY_DATA_9F20, "Track 2 Discretionary Data", 0x9F20, 0, 16, PERM_K | PERM_RA);
DECL_TAG_CN(ASRPD_9F0A, "Application Selection Registered Proprietary Data", 0x9F0A, 0, 253, PERM_K | PERM_RA);
DECL_TAG_B(FFI_9F6E, "Form Factor Indicator", 0x9F6E, 4, 4);
DECL_TAG_B(TORN_RECORD_FF8101, "Torn Record", 0xFF8101, 0, 255);
DECL_TAG_B(CUSTOMER_EXCLUSIVE_DATA_9F7C, "Customer Exclusive Data (CED)", 0x9F7C, 0, 32, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(SDA_TAG_LIST_9F4A, "Static Data Authentication (SDA) Tag List", 0x9F4A, 0, 252, PERM_K | PERM_RA);
DECL_TAG_B(ICC_DYNAMIC_NUMBER_9F4C, "ICC Dynamic Number", 0x9F4C, 2, 8, PERM_K | PERM_RA);
DECL_TAG_B(DATA_AUTHENTICATION_CODE_9F45, "Data Authentication Code", 0x9F45, 2, 2);
DECL_TAG_B(ICC_PUB_KEY_EXP_9F47, "ICC Public Key Exponent", 0x9F47, 1, 3,
           PERM_K | PERM_RA);
DECL_TAG_B(ICC_PUB_KEY_REMAINER_9F48, "Integrated Circuit Modulus Remainder", 0x9F48, 0, 252,
           PERM_K | PERM_RA);
DECL_TAG_B(ISSUER_PUB_KEY_REMAINER_92, "Issuer Public Key Remainder", 0x92, 0, 252,
           PERM_K | PERM_RA);
DECL_TAG_B(ISSUER_PUB_KEY_EXP_9F32, "Issuer Public Key Exponent", 0x9F32, 1, 3,
           PERM_K | PERM_RA);
DECL_TAG_B(ICC_PUB_KEY_CERT_9F46, "ICC Public Key Certificate", 0x9F46, 0, 252,
           PERM_K | PERM_RA);
DECL_TAG_B(ISSUER_PUB_KEY_CERT_90, "Issuer Public Key Certificate", 0x90, 0, 252,
           PERM_K | PERM_RA);
DECL_TAG_B(ATC_9F36, "Application Transaction Counter (ATC)", 0x9F36, 2, 2,
           PERM_K | PERM_RA);
DECL_TAG_B(APPLICATION_CRYPTOGRAM_9F26, "Application Cryptogram", 0x9F26, 8, 8,
           PERM_K | PERM_RA);
DECL_TAG_B(SDAD_9F4B, "Signed Dynamic Application Data", 0x9F4B, 0, 252, PERM_K | PERM_RA);
DECL_TAG_B(SIGNED_STATIC_APPLICATION_DATA_93, "Signed Static Application Data", 0x93, 0, 252);
DECL_TAG_B(DF_NAME_84, "Dedicated File (DF) Name", 0x84, 5, 16, PERM_K | PERM_RA);
DECL_TAG_B(IDSD_D2, "Integrated Data Storage Directory (IDSD)", 0xD2, 0, 252);
DECL_TAG_B(PDOL_9F38, "Processing Options Data Object List (PDOL)", 0x9F38, 0, 252, PERM_K | PERM_RA);
DECL_TAG_B(APPLICATION_TEMPLATE_61, "Application Template", 0x61, 0, 252);
DECL_TAG_B(EXTENDED_SELECTION_9F29, "Extended Selection", 0x9F29, 0, 16);
DECL_TAG_B(UNPREDICTABLE_NUMBER_9F37, "Unpredictable Number", 0x9F37, 4, 4);
DECL_TAG_B(APPLICATION_VERSION_NUMBER_CARD_9F08, "Application Version Number (Card)", 0x9F08, 2, 2, PERM_K | PERM_RA);
DECL_TAG_B(APPLICATION_VERSION_NUMBER_READER_9F09, "Application Version Number (Reader)", 0x9F09, 2, 2);
DECL_TAG_B(CDOL1_8C, "CDOL1", 0x8C, 0, 250, PERM_K | PERM_RA);
DECL_TAG_B(CDOL1_RELATED_DATA_DF8107, "CDOL1 Related Data", 0xDF8107, 0, 252);
DECL_TAG_B(CVC3_TRACK1_9F60, "CVC3 (Track1)", 0x9F60, 2, 2, PERM_K | PERM_RA);
DECL_TAG_B(CVC3_TRACK2_9F61, "CVC3 (Track2)", 0x9F61, 2, 2, PERM_K | PERM_RA);
DECL_TAG_B(CVM_LIST_8E, "CVM List", 0x8E, 10, 250, PERM_K | PERM_RA);
DECL_TAG_B(DATA_NEEDED_DF8106, "Data Needed", 0xDF8106, 0, 255);
DECL_TAG_B(DATA_RECORD_FF8105, "Data Record", 0xFF8105, 0, 255);
DECL_TAG_B(DATA_TO_SEND_FF8104, "Data To Send", 0xFF8104, 0, 255);
DECL_TAG_B(DISCRETIONARY_DATA_FF8106, "Discretionary Data", 0xFF8106, 0, 255);
DECL_TAG_B(DEFAULT_UDOL_DF811A, "Default UDL", 0xDF8111A, 3, 3);
DECL_TAG_B(DEVICE_ESTIMATED_TRANSMISSION_TIME_DF8305, "Device Estimated Transmission Time", 0xDF8305, 2, 2, PERM_K | PERM_RA);
DECL_TAG_B(DEVIDE_REPLAY_RESISTENCE_ENTROPY_DF8302, "Device Relay Resistence Entroyp", 0xDF8302, 4, 4, PERM_K | PERM_RA);
DECL_TAG_B(DRDOL_9F51, "DRDOL", 0x9F51, 0, 250, PERM_K | PERM_RA);
DECL_TAG_B(DRDOL_RELATED_DATA_DF8113, "DRDOL Related Data", 0xDF8113, 0, 255);
DECL_TAG_B(DS_DIGEST_H_DF61, "DS Digest H", 0xDF61, 8, 8);
DECL_TAG_B(DSDOL_9F5B, "DSDOL", 0x9F5B, 0, 250, PERM_K | PERM_RA);
DECL_TAG_B(DS_INPUT_CARD_DF60, "DS Input (Card)", 0xDF60, 8, 8,
           PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(DS_INPUT_TERM_DF8109, "DS Input (Term)", 0xDF8109, 8, 8,
           PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(DS_ODS_CARD_9F54, "DS ODS Card", 0x9F54, 0, 160, PERM_K | PERM_RA);
DECL_TAG_B(DS_ODS_INFO_DF62, "DS ODS Info", 0xDF62, 1, 1, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(DS_ODS_TERM_DF63, "DS ODS Term", 0xDF63, 0, 160, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(DS_REQUESTED_OPERATOR_ID_9F5C, "DS Requested Operator ID", 0x9F5C, 8, 8,
           PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(DS_SLOT_AVAILABILITY_9F5F, "DS Slot Availability", 0x9F5F, 1, 1,
           PERM_K | PERM_RA);
DECL_TAG_B(DS_SUMMARY_1_9F7D, "DS Summary 1", 0x9F7D, 8, 16, PERM_K | PERM_RA);
DECL_TAG_B(DS_SUMMARY_2_DF8101, "DS Summary 2", 0xDF8101, 8, 16, PERM_K | PERM_RA);
DECL_TAG_B(DS_SUMMARY_3_DF8102, "DS Summary 3", 0xDF8102, 8, 16, PERM_K | PERM_RA);
DECL_TAG_B(DS_UNPREDICTABLE_NUMBER_9F7F, "DS Unpredictable Number", 0x9F7F, 4, 4,
           PERM_K | PERM_RA);
DECL_TAG_B(DSVN_TERM_DF810D, "DSVN Term", 0xDF810D, 0, 252);
DECL_TAG_B(HOLD_TIME_VALUE_DF8130, "Hold Time Value", 0xDF8130, 1, 1);
DECL_TAG_B(IAC_DEFAULT_9F0D, "Issuer Action Code - Default", 0x9F0D, 5, 5,
           PERM_K | PERM_RA);
DECL_TAG_B(IAC_DENIAL_9F0E, "Issuer Action Code - Denial", 0x9F0E, 5, 5,
           PERM_K | PERM_RA);
DECL_TAG_B(IAC_ONLINE_9F0F, "Issuer Action Code - Online", 0x9F0F, 5, 5,
           PERM_K | PERM_RA);
DECL_TAG_B(KERNEL_ID_DF810C, "Kernel ID", 0xDF810C, 1, 1);
DECL_TAG_B(LOG_ENTRY_9F4D, "Log Entry", 0x9F4D, 2, 2, PERM_K | PERM_RA);
DECL_TAG_B(MS_APPLICATION_VERSION_NUMBER_READER_9F6D, "Mag-stripe Application Version Number (Reader)", 0x9F6D, 2, 2);
DECL_TAG_B(MAX_RELAY_RESISTENCE_GRACE_PERIOD_DF8133, "Maximum Relay Resistance Grace Period", 0xDF8133, 2, 2);
DECL_TAG_B(MAX_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8304, "Max Time For Processing Relay Resistance APDU", 0xDF8304, 2, 2, PERM_K | PERM_RA);
DECL_TAG_B(MIN_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8303, "Max Time For Processing Relay Resistance APDU", 0xDF8303, 2, 2, PERM_K | PERM_RA);

DECL_TAG_B(MAX_LIFETIME_OF_TORN_RECORD_DF811C, "Max Lifetime of Torn Transaction Log Record", 0xDF811C, 2, 2);
DECL_TAG_B(MAX_NUMBER_OF_TORN_RECORDS_DF811D, "Max Number of Torn Transaction Log Records", 0xDF811D, 1, 1);
DECL_TAG_B(MEASURED_RELAY_RESISTENCE_PROCESSING_TIME_DF8306, "Measured Relay Resistance Processing Time", 0xDF8306, 2, 2);
DECL_TAG_B(MIN_RELAY_RESISTENCE_GRACE_PERIOD_DF8132, "Minimum Relay Resistance Grace Period", 0xDF8132, 2, 2);
DECL_TAG_B(NATC_TRACK1_9F64, "NATC (Track 1)", 0x9F64, 1, 1, PERM_K | PERM_RA);
DECL_TAG_B(NATC_TRACK2_9F67, "NATC (Track 2)", 0x9F67, 1, 1, PERM_K | PERM_RA);
DECL_TAG_B(PCVC3_TRACK1_9F62, "PCVC3 (Track1)", 0x9F62, 6, 6, PERM_K | PERM_RA);
DECL_TAG_B(PUNATC_TRACK1_9F63, "PUNATC(Track1)", 0x9F63, 6, 6, PERM_K | PERM_RA);
DECL_TAG_B(PCVC3_TRACK2_9F65, "PCVC3 (Track2)", 0x9F65, 2, 2, PERM_K | PERM_RA);
DECL_TAG_B(PDOL_RELATED_DATA_DF8111, "PDOL Related Data", 0xDF8111, 0, 255);
DECL_TAG_B(PHONE_MESSAGE_TABLE_DF8131, "Phone Message Table", 0xDF8131, 0, 255);
DECL_TAG_B(PROCEED_TO_FIRST_WRITE_FLAG_DF8110, "Proceed To First Write Flag", 0xDF8110, 1, 1, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(PROTECTED_DATA_ENVELOPE1_9F70, "Protected Data Envelope 1", 0x9F70, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(PROTECTED_DATA_ENVELOPE2_9F71, "Protected Data Envelope 2", 0x9F71, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(PROTECTED_DATA_ENVELOPE3_9F72, "Protected Data Envelope 3", 0x9F72, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(PROTECTED_DATA_ENVELOPE4_9F73, "Protected Data Envelope 4", 0x9F73, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(PROTECTED_DATA_ENVELOPE5_9F74, "Protected Data Envelope 5", 0x9F74, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);

DECL_TAG_B(UNPROTECTED_DATA_ENVELOPE1_9F75, "Unprotected Data Envelope 1", 0x9F75, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(UNPROTECTED_DATA_ENVELOPE2_9F76, "Unprotected Data Envelope 2", 0x9F76, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(UNPROTECTED_DATA_ENVELOPE3_9F77, "Unprotected Data Envelope 3", 0x9F77, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(UNPROTECTED_DATA_ENVELOPE4_9F78, "Unprotected Data Envelope 4", 0x9F78, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);
DECL_TAG_B(UNPROTECTED_DATA_ENVELOPE5_9F79, "Unprotected Data Envelope 5", 0x9F79, 0, 192, PERM_K | PERM_RA | PERM_ACT | PERM_DET);

DECL_TAG_B(RELAY_RESISTENCE_ACCURACY_THRESHOLD_DF8136, "Relay Resistence Accurancy Threshold", 0xDF8136, 2, 2);
DECL_TAG_B(RELAY_RESISTENCE_TRANSMISSION_TIME_MISMATCH_THRESHOLD_DF8137, "Relay Resistance Transmission Time MismatchThreshold", 0xDF8137, 1, 1);
DECL_TAG_B(RRP_COUNTER_DF8307, "RRP Counter", 0xDF8307, 1, 1);
DECL_TAG_B(TAGS_TO_READ_DF8112, "Tags ToRead", 0xDF8112, 0, 255, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(TAGS_TO_WRITE_AFTER_GEN_AC_FF8103, "Tags To Write After Gen AC", 0xFF8103, 0, 255, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(TAGS_TO_WRITE_BEFORE_GEN_AC_FF8102, "Tags To Write Before Gen AC", 0xFF8120, 0, 255, PERM_K | PERM_ACT | PERM_DET);
DECL_TAG_B(TAC_DEFAULT_DF8120, "Terminal Action Code - Default", 0xDF8120, 5, 5);
DECL_TAG_B(TAC_DENIAL_DF8121, "Terminal Action Code - Denial", 0xDF8121, 5, 5);
DECL_TAG_B(TAC_ONLINE_DF8122, "Terminal Action Code - Online", 0xDF8122, 5, 5);
DECL_TAG_B(TERMINAL_EXPECTED_TRANSMISSION_TIME_FOR_C_APDU_DF8134, "Terminal Expected Transmission Time For Relay Resistance C-APDU", 0xDF8134, 2, 2);
DECL_TAG_B(TERMINAL_EXPECTED_TRANSMISSION_TIME_FOR_R_APDU_DF8135, "Terminal Expected Transmission Time For Relay Resistance R-APDU", 0xDF8135, 2, 2);
DECL_TAG_B(TERMINAL_RELAY_RESISTENCE_ENTROPY_DF8301, "Terminal Rely Resistence Entropy", 0xDF8301, 4, 4);
DECL_TAG_B(TERMINAL_RISK_MANAGEMENT_DATA_9F1D, "Terminal Risk Management Data", 0x9F1D, 8, 8);
DECL_TAG_B(TIME_OUT_VALUE_DF8127, "Time Out Value", 0xDF8127, 2, 2);
DECL_TAG_B(RESPONSE_TEMPLATE_FORMAT_1_80, "Response Message Template Format 1", 0x80, 0, 253, PERM_K | PERM_RA);
DECL_TAG_B(RESPONSE_TEMPLATE_FORMAT_2_77, "Response Message Template Format 2", 0x77, 0, 253, PERM_K | PERM_RA);
DECL_TAG_B(READ_RECORD_RESPONSE_TEMPLATE_70, "Read Record Response Message Template", 0x70, 0, 253, PERM_K | PERM_RA);

DECL_TAG_VAR(DIRECTORY_ENTRY_61, "Directory Entry", 0x61, 0, 255);
DECL_TAG_VAR(FCI_ISSUER_DISCRETIONARY_DATA_BF0C, "File Control Information (FCI) Issuer Discretionary Data", 0xBF0C, 0, 223, PERM_K | PERM_RA);
DECL_TAG_VAR(FCI_PROPRIETARY_TEMPLATE_A5, "File Control Information (FCI) Proprietary Template", 0xA5, 0, 255, PERM_K | PERM_RA);
DECL_TAG_VAR(FCI_TEMPLATE_6F, "File Control Information (FCI) Template", 0x6F, 0, 252,
             PERM_K | PERM_RA);

DECL_TAG_ANS(APPLICATION_LABEL_50, "Application Label", 0x50, 1, 16, PERM_K | PERM_RA);
DECL_TAG_ANS(MERCHANT_NAME_AND_LOCATION_9F4E, "Merchant Name and Location", 0x9F4E, 0, 252);
DECL_TAG_ANS(APP_PREFERRED_NAME_9F12, "Application Preferred Name", 0x9F12, 1, 16,
             PERM_K | PERM_RA);
DECL_TAG_ANS(DD_CARD_TRACK1_DF812A, "DD Card (Track1)", 0xDF812A, 0, 56);
DECL_TAG_ANS(MERCHANT_IDENTIFIER_9F16, "Merchant Identifier", 0x9F16, 15, 15);
DECL_TAG_ANS(TRACK1_DISCRETIONARY_DATA_9F1F, "Track 1 Discretionary Data", 0x9F1F, 0, 54, PERM_K | PERM_RA);
DECL_TAG_AN(LANG_PREF_5F2D, "Language Preference", 0x5F2D, 2, 8,
            PERM_K | PERM_RA);
DECL_TAG_AN(INTERFACE_DEVICE_SERIAL_NUMBER_9F1E, "Interface Device Serial Number", 0x9F1E, 8, 8);
DECL_TAG_AN(PAYMENT_ACCOUNT_REFERENCE_9F24, "Payment Account Reference", 0x9F24, 29, 29, (PERM_K | PERM_RA));
DECL_TAG_AN(TERMINAL_IDENTIFICATION_9F1C, "Terminal Identification", 0x9F1C, 8, 8);
DECL_TAG_AN(TRANSACTION_CATEGORY_CODE_9F53, "Transaction Category Code", 0x9F53, 1, 1, PERM_K | PERM_ACT | PERM_DET);

enum class AC_TYPE : uint8_t {
    AAC = 0,
    TC = 1,
    ARQC = 2,
    RFU = 3
};

enum class CVM_CODE : uint8_t {
    FAILED_CVM_PROCESSING = 0,
    PLAINTEXT_PIN_VERIFICATION_PERFORMED_BY_ICC = 1,
    ENCIPHERED_PIN_VERIFIED_ONLINE = 2,
    PLAINTEXT_PIN_VERIFICATION_PERFORMED_BY_ICC_AND_SIGNATURE = 3,
    ENCIPHERED_PIN_VERIFICATION_PERFORMED_BY_ICC = 4,
    ENCIPHERED_PIN_VERIFICATION_PERFORMED_BY_ICC_AND_SIGNATURE = 5,
    SIGNATURE = 0x1E,
    NO_CVM_REQUIRED = 0x1F,
    NO_CVM_PERFORMED = 0x3F
};

enum class CVM_CONDITION : uint8_t {
    ALWAYS = 0,
    IF_UNATTENDED_CASH = 1,
    IF_NOT_UNATTENDED_CASH_NOT_MANUAL_CASH_NOT_PURCHASE_WITH_CASHBACK = 2,
    IF_TERMINAL_SUPPORTS_THE_CVM = 3,
    IF_MANUAL_CASH = 4,
    IF_PURCHASE_WITH_CASHBACK = 5,
    IF_APPLICATION_CURRENCY_AND_UNDER_X = 6,
    IF_APPLICATION_CURRENCY_AND_OVER_X = 7,
    IF_APPLICATION_CURRENCY_AND_UNDER_Y = 8,
    IF_APPLICATION_CURRENCY_AND_OVER_Y = 9
};

enum class CVM_RESULT : uint8_t {
    UNKNOWN = 0,
    FAILED = 1,
    SUCCESSFUL = 2
};

static constexpr char THIRD_PARTY_DATA_9F6E_desc[] = "Third Party Data";
struct TAG_THIRD_PARTY_DATA_9F6E : public tag_b {
    constexpr TAG_THIRD_PARTY_DATA_9F6E() : tag_b(0x9F6E, THIRD_PARTY_DATA_9F6E_desc, 5, 32,
                                                  PERM_K | PERM_RA){};
    static inline std::vector<uint8_t> get_counry_code(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>{v.begin(), v.begin() + 2};
    }

    static inline std::vector<uint8_t> get_unique_identifier(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>{v.begin() + 2, v.begin() + 4};
    }

    static inline bool has_device_type(const std::vector<uint8_t>& v) {
        return (v[2] & 0x80) == 0x00;
    }

    static inline std::vector<uint8_t> get_device_type(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>{v.begin() + 4, v.begin() + 6};
    }
};
static constexpr TAG_THIRD_PARTY_DATA_9F6E THIRD_PARTY_DATA_9F6E{};

static constexpr char DS_SUMMARY_STATUS_DF810B_desc[] = "DS Summary Status";
struct TAG_DS_SUMMARY_STATUS_DF810B : public tag_b {
    constexpr TAG_DS_SUMMARY_STATUS_DF810B() : tag_b(0xDF810B, DS_SUMMARY_STATUS_DF810B_desc, 1, 1){};

    DECL_TAG_BIT(read, 1, 8);
    DECL_TAG_BIT(write, 1, 7);

    static constexpr std::array<const tag_bit_field*, 2> all_bits = {
        &read,
        &write};
};
static constexpr TAG_DS_SUMMARY_STATUS_DF810B DS_SUMMARY_STATUS_DF810B{};

static constexpr char CVM_RESULT_9F34_desc[] = "CVM Results";
struct TAG_CVM_RESULT_9F34 : public tag_b {
    constexpr TAG_CVM_RESULT_9F34() : tag_b(0x9F34, CVM_RESULT_9F34_desc, 3, 3){};
    static inline void set_performed(std::vector<uint8_t>& v, CVM_CODE code) {
        v[0] = static_cast<uint8_t>(code);
    }

    static inline void set_condition(std::vector<uint8_t>& v, CVM_CONDITION code) {
        v[1] = static_cast<uint8_t>(code);
    };

    static inline void set_result(std::vector<uint8_t>& v, CVM_RESULT code) {
        v[2] = static_cast<uint8_t>(code);
    };
};
static constexpr TAG_CVM_RESULT_9F34 CVM_RESULT_9F34{};

static constexpr char DS_ODS_INFO_FOR_READER_DF810A_desc[] = "DS ODS Info For Reader";
struct TAG_DS_ODS_INFO_FOR_READER_DF810A : public tag_b {
    constexpr TAG_DS_ODS_INFO_FOR_READER_DF810A() : tag_b(0xDF810A, DS_ODS_INFO_FOR_READER_DF810A_desc, 1, 1,
                                                          PERM_K | PERM_ACT | PERM_DET){};
    DECL_TAG_BIT(usable_for_tc, 1, 8);
    DECL_TAG_BIT(usable_for_arqc, 1, 7);
    DECL_TAG_BIT(usable_for_aac, 1, 6);
    DECL_TAG_BIT(stop_if_no_ds_ods_term, 1, 3);
    DECL_TAG_BIT(stop_if_write_failed, 1, 2);

    static constexpr std::array<const tag_bit_field*, 5> all_bits = {
        &usable_for_tc,
        &usable_for_arqc,
        &usable_for_aac,
        &stop_if_no_ds_ods_term,
        &stop_if_write_failed};
};
static constexpr TAG_DS_ODS_INFO_FOR_READER_DF810A DS_ODS_INFO_FOR_READER_DF810A{};

static constexpr char DS_AC_TYPE_DF8108_desc[] = "DS AC Type";
struct TAG_DS_AC_TYPE_DF8108 : public tag_b {
    constexpr TAG_DS_AC_TYPE_DF8108() : tag_b(0xDF8108, DS_AC_TYPE_DF8108_desc, 1, 1,
                                              PERM_K | PERM_ACT | PERM_DET){};
    static AC_TYPE custom_value(const std::vector<uint8_t>& v) {
        return static_cast<AC_TYPE>(v[0] >> 6);
    };
};
static constexpr TAG_DS_AC_TYPE_DF8108 DS_AC_TYPE_DF8108{};

static constexpr char REFERENCE_CONTROL_PARAMETER_DF8114_desc[] = "Reference Control Parameter";
struct TAG_REFERENCE_CONTROL_PARAMETER_DF8114 : public tag_b {
    constexpr TAG_REFERENCE_CONTROL_PARAMETER_DF8114() : tag_b(0xDF8114, REFERENCE_CONTROL_PARAMETER_DF8114_desc, 1, 1){};
    DECL_TAG_BIT(cda_signature_requested, 1, 5);
    static inline void set_ac_type(std::vector<uint8_t>& v, AC_TYPE ac_type) {
        v[0] |= (static_cast<uint8_t>(ac_type) << 6);
    };

    static inline AC_TYPE get_ac_type(const std::vector<uint8_t>& v) {
        return static_cast<AC_TYPE>(v[0] >> 6);
    };

    static constexpr std::array<const tag_bit_field*, 1> all_bits = {
        &cda_signature_requested};
};
static constexpr TAG_REFERENCE_CONTROL_PARAMETER_DF8114 REFERENCE_CONTROL_PARAMETER_DF8114{};

static constexpr char DS_SLOT_MANAGEMENT_CONTROL_9F6F_desc[] = "DS Slot Management Control";
struct TAG_DS_SLOT_MANAGEMENT_CONTROL_9F6F : public tag_b {
    constexpr TAG_DS_SLOT_MANAGEMENT_CONTROL_9F6F() : tag_b(0x9F6F, DS_SLOT_MANAGEMENT_CONTROL_9F6F_desc, 1, 1, PERM_K | PERM_RA){};

    DECL_TAG_BIT(permanent_slot_type, 1, 8);
    DECL_TAG_BIT(volatile_slot_type, 1, 7);
    DECL_TAG_BIT(low_volatility, 1, 6);
    DECL_TAG_BIT(locked_slot, 1, 5);
    DECL_TAG_BIT(deactivated_slot, 1, 1);
    static constexpr std::array<const tag_bit_field*, 5> all_bits = {
        &permanent_slot_type,
        &volatile_slot_type,
        &low_volatility,
        &locked_slot,
        &deactivated_slot};
};
static constexpr TAG_DS_SLOT_MANAGEMENT_CONTROL_9F6F DS_SLOT_MANAGEMENT_CONTROL_9F6F{};

static constexpr char IDS_STATUS_DF8128_desc[] = "IDS Status";
struct TAG_IDS_STATUS_DF8128 : public tag_b {
    constexpr TAG_IDS_STATUS_DF8128() : tag_b(0xDF8128, IDS_STATUS_DF8128_desc, 1, 1){};

    DECL_TAG_BIT(read, 1, 8);
    DECL_TAG_BIT(write, 1, 7);
    static constexpr std::array<const tag_bit_field*, 2> all_bits = {
        &read,
        &write};

    static inline void clear_read(std::vector<uint8_t>& v) {
        v[0] &= ~0x80;
    };
};
static constexpr TAG_IDS_STATUS_DF8128 IDS_STATUS_DF8128{};

static constexpr char USER_INTERFACE_REQUEST_DATA_DF8116_desc[] = "User Interface Request Data";
struct TAG_USER_INTERFACE_REQUEST_DATA_DF8116 : public tag_b {
    constexpr TAG_USER_INTERFACE_REQUEST_DATA_DF8116() : tag_b(0xDF8116, USER_INTERFACE_REQUEST_DATA_DF8116_desc, 22, 22){};
    static std::vector<uint8_t> get_default() {
        std::vector<uint8_t> v(22);
        set_message_id(v, ui_message_id::NA);
        set_status(v, ui_status_id::NA);
        set_value_qualifier(v, ui_value_id::NONE);
        return v;
    };

    static inline void set_message_id(std::vector<uint8_t>& v, ui_message_id id) {
        v[0] = static_cast<uint8_t>(id);
    };

    static inline ui_message_id get_message_id(const std::vector<uint8_t>& v) {
        return static_cast<ui_message_id>(v[0]);
    };

    static inline void set_status(std::vector<uint8_t>& v, ui_status_id id) {
        v[1] = static_cast<uint8_t>(id);
    };

    static inline ui_status_id get_status(const std::vector<uint8_t>& v) {
        return static_cast<ui_status_id>(v[1]);
    };

    // n6
    static inline void set_hold_time(std::vector<uint8_t>& v, const std::vector<uint8_t>& time){
        if (time.size() != 3) {
            pr_error("bad hold time\n");
            throw std::bad_exception();
        }
        std::copy(time.begin(), time.end(), v.begin() + 2);
    };

    static inline std::vector<uint8_t> get_hold_time(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>(v.begin() + 2, v.begin() + 5);
    };

    static inline void set_lang_pref(std::vector<uint8_t>& v, const std::vector<uint8_t>& pref) {
        if (pref.size() > 8) {
            pr_error("bad lang pref\n");
            throw std::bad_exception();
        }

        std::copy(pref.begin(), pref.end(), v.begin() + 5);
    };

    static inline std::vector<uint8_t> get_lang_pref(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>(v.begin() + 5, v.begin() + 13);
    };

    static inline void set_value_qualifier(std::vector<uint8_t>& v, ui_value_id qualifier) {
        v[13] = static_cast<uint8_t>(qualifier);
    };

    static inline ui_value_id get_value_qualifier(const std::vector<uint8_t>& v) {
        return static_cast<ui_value_id>(v[13]);
    };

    // n12
    static inline void set_value(std::vector<uint8_t>& v, const std::vector<uint8_t>& value) {
        if (value.size() != 6) {
            pr_error("bad value\n");
            throw std::bad_exception();
        }
        std::copy(value.begin(), value.end(), v.begin() + 14);
    };

    static inline std::vector<uint8_t> get_value(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>{v.begin() + 14, v.begin() + 20};
    };

    // n3
    static inline void set_currency_code(std::vector<uint8_t>& v, const std::vector<uint8_t>& code) {
        std::copy(code.begin(), code.end(), v.begin() + 20);
    };

    static inline std::vector<uint8_t> get_currency_code(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>{v.begin() + 20, v.end()};
    };

    static ui_req_data to_ui_req_data(const std::vector<uint8_t>& v) {
        ui_req_data ui;
        ui.ui_id = get_message_id(v);
        ui.status = get_status(v);
        ui.hold_time = tag_n::to_numeric_value(get_hold_time(v));
        ui.value_type = get_value_qualifier(v);
        if (ui.value_type != ui_value_id::NONE) {
            ui.value = vector2hex(get_value(v));
            ui.currency_code = vector2hex(get_currency_code(v));
            ui.lang = vector2hex(get_lang_pref(v));
        };
        return ui;
    };

    static void print(const std::vector<uint8_t>& v, const std::string prefix = std::string{}) {
        pr_debug(prefix, "MESSAGE  [", emv::to_string(get_message_id(v)), "]\n");
        pr_debug(prefix, "STATUS [", emv::to_string(get_status(v)), "]\n");
        pr_debug(prefix, "HOLD TIME ", get_hold_time(v), "\n");
        if (get_value_qualifier(v) != ui_value_id::NONE)
            pr_debug(emv::to_string(get_value_qualifier(v)), " ", get_value(v), " [", get_currency_code(v), "]\n");

        pr_debug("\n");
    };
};
static constexpr TAG_USER_INTERFACE_REQUEST_DATA_DF8116 USER_INTERFACE_REQUEST_DATA_DF8116{};

static constexpr char ERROR_INDICATION_DF8115_desc[] = "Error Indication";
struct TAG_ERROR_INDICATION_DF8115 : public tag_b {
    constexpr TAG_ERROR_INDICATION_DF8115() : tag_b(0xDF8115, ERROR_INDICATION_DF8115_desc, 6, 6){};
    static std::vector<uint8_t> get_default() {
        std::vector<uint8_t> v(6);
        set_msg_on_error(v, ui_message_id::NA);
        return v;
    };

    static inline void set_l1_error(std::vector<uint8_t>& v, L1_ERROR error) {
        v[0] = static_cast<uint8_t>(error);
    };

    static inline void set_l2_error(std::vector<uint8_t>& v, L2_ERROR error) {
        v[1] = static_cast<uint8_t>(error);
    };

    static inline void set_l3_error(std::vector<uint8_t>& v, L3_ERROR error) {
        v[2] = static_cast<uint8_t>(error);
    };

    static inline void set_sw12(std::vector<uint8_t>& v, uint8_t sw1, uint8_t sw2) {
        v[3] = sw1;
        v[4] = sw2;
    };

    static inline void set_msg_on_error(std::vector<uint8_t>& v, ui_message_id id) {
        v[5] = static_cast<uint8_t>(id);
    };
};
static constexpr TAG_ERROR_INDICATION_DF8115 ERROR_INDICATION_DF8115{};

static constexpr char OUTCOME_PARAMETER_SET_DF8129_desc[] = "Outcome Parameter set";
struct TAG_OUTCOME_PARAMETER_SET_DF8129 : public tag_b {
    constexpr TAG_OUTCOME_PARAMETER_SET_DF8129() : tag_b(0xDF8129, OUTCOME_PARAMETER_SET_DF8129_desc, 8, 8){};

    static std::vector<uint8_t> get_default() {
        std::vector<uint8_t> v(8);
        v[0] = 0xF0;
        v[1] = 0xF0;
        v[2] = 0xF0;
        v[3] = 0xF0;
        v[5] = 0xF0;
        v[6] = 0xFF;
        return v;
    };

    static inline void set_status(std::vector<uint8_t>& v, OUTCOME_TYPE status) {
        v[0] &= 0x0F;
        v[0] |= static_cast<uint8_t>(status) << 4;
    };

    static inline OUTCOME_TYPE get_status(const std::vector<uint8_t>& v) {
        return static_cast<OUTCOME_TYPE>(v[0] >> 4);
    };

    static inline void set_start(std::vector<uint8_t>& v, RESTART_POINT start) {
        v[1] &= 0x0F;
        v[1] |= static_cast<uint8_t>(start) << 4;
    };

    static inline RESTART_POINT get_start(const std::vector<uint8_t>& v) {
        return static_cast<RESTART_POINT>(v[1] >> 4);
    };

    static inline void set_cvm(std::vector<uint8_t>& v, OUTCOME_CVM cvm) {
        v[3] &= 0x0F;
        v[3] |= static_cast<uint8_t>(cvm) << 4;
    };

    static inline OUTCOME_CVM get_cvm(const std::vector<uint8_t>& v) {
        return static_cast<OUTCOME_CVM>(v[3] >> 4);
    };

    DECL_TAG_BIT(ui_request_on_outcome_present, 5, 8);
    DECL_TAG_BIT(ui_request_on_restart_present, 5, 7);
    DECL_TAG_BIT(data_record_present, 5, 6);
    DECL_TAG_BIT(discretionary_data_present, 5, 5);
    DECL_TAG_BIT(receipt_required, 5, 4);

    static constexpr std::array<const tag_bit_field*, 5> all_bits = {
        &ui_request_on_outcome_present,
        &ui_request_on_restart_present,
        &data_record_present,
        &discretionary_data_present,
        &receipt_required};

    static inline void set_field_off(std::vector<uint8_t>& v, uint8_t time) {
        v[6] = time;
    };

    static inline uint8_t get_field_off(const std::vector<uint8_t>& v) {
        return v[6];
    };

    static inline void set_removal_timerout(std::vector<uint8_t>& v, uint8_t time) {
        v[7] = time;
    };

    static inline uint8_t get_removal_timerout(const std::vector<uint8_t>& v) {
        return v[7];
    };

    static void print(const std::vector<uint8_t>& v,
                      const std::string prefix = std::string{}) {
        pr_debug(prefix, emv::to_string(get_status(v)), "\n");
        pr_debug(prefix, "START [", emv::to_string(get_start(v)), "]\n");
        pr_debug(prefix, "CVM [", emv::to_string(get_cvm(v)), "]\n");
        pr_debug(prefix, "field off [", to_hex(static_cast<int>(get_field_off(v))), "]");
        pr_debug(prefix, "removal timeout [", to_hex(static_cast<int>(get_removal_timerout(v))), "]\n");
        pr_debug(prefix);
        DUMP(v);
        pr_debug("\n");
    };
};
static constexpr TAG_OUTCOME_PARAMETER_SET_DF8129 OUTCOME_PARAMETER_SET_DF8129{};

static constexpr char TVR_95_desc[] = "Terminal Verification Results";
struct TAG_TVR_95 : public tag_b {
    constexpr TAG_TVR_95() : tag_b(0x95, TVR_95_desc, 5, 5){};
    DECL_TAG_BIT(oda_not_performed, 1, 8);
    DECL_TAG_BIT(sda_failed, 1, 7);
    DECL_TAG_BIT(icc_data_missing, 1, 6);
    DECL_TAG_BIT(card_on_exception_file, 1, 5);
    DECL_TAG_BIT(dda_failed, 1, 4);
    DECL_TAG_BIT(cda_failed, 1, 3);
    DECL_TAG_BIT(icc_terminal_different_app_versions, 2, 8);
    DECL_TAG_BIT(expired_application, 2, 7);
    DECL_TAG_BIT(application_not_effective, 2, 6);
    DECL_TAG_BIT(requested_service_not_allowd_for_card, 2, 5);
    DECL_TAG_BIT(new_card, 2, 4);
    DECL_TAG_BIT(cardholder_verification_not_successful, 3, 8);
    DECL_TAG_BIT(unrecognized_cvm, 3, 7);
    DECL_TAG_BIT(pin_try_limit_exceeded, 3, 6);
    DECL_TAG_BIT(pin_entry_required_and_pinpad_not_working, 3, 5);
    DECL_TAG_BIT(pin_entry_required_pinpad_present_but_pin_now_entered, 3, 4);
    DECL_TAG_BIT(online_pin_entered, 3, 3);
    DECL_TAG_BIT(transaction_exceeds_floor_limit, 4, 8);
    DECL_TAG_BIT(low_consecutive_offline_limit_exceeded, 4, 7);
    DECL_TAG_BIT(upper_consecutive_offline_limit_exceeded, 4, 6);
    DECL_TAG_BIT(transaction_randomly_selected_for_online, 4, 5);
    DECL_TAG_BIT(merchant_forced_transaction_online, 4, 4);
    DECL_TAG_BIT(default_tdol_used, 5, 8);
    DECL_TAG_BIT(issuer_authentication_failed, 5, 7);
    DECL_TAG_BIT(script_processing_failed_before_final_gen_ac, 5, 6);
    DECL_TAG_BIT(script_processing_failed_after_final_gen_ac, 5, 5);
    DECL_TAG_BIT(relay_resistance_threshold_exceeded, 5, 4);
    DECL_TAG_BIT(relay_resistence_time_limits_exceeded, 5, 3);
    static constexpr std::array<const tag_bit_field*, 28> all_bits = {
        &oda_not_performed,
        &sda_failed,
        &icc_data_missing,
        &card_on_exception_file,
        &dda_failed,
        &cda_failed,
        &icc_terminal_different_app_versions,
        &expired_application,
        &application_not_effective,
        &requested_service_not_allowd_for_card,
        &new_card,
        &cardholder_verification_not_successful,
        &unrecognized_cvm,
        &pin_try_limit_exceeded,
        &pin_entry_required_and_pinpad_not_working,
        &pin_entry_required_pinpad_present_but_pin_now_entered,
        &online_pin_entered,
        &transaction_exceeds_floor_limit,
        &low_consecutive_offline_limit_exceeded,
        &upper_consecutive_offline_limit_exceeded,
        &transaction_randomly_selected_for_online,
        &merchant_forced_transaction_online,
        &default_tdol_used,
        &issuer_authentication_failed,
        &script_processing_failed_before_final_gen_ac,
        &script_processing_failed_after_final_gen_ac,
        &relay_resistance_threshold_exceeded,
        &relay_resistence_time_limits_exceeded};

    enum class RRP_STATUS : uint8_t {
        NOT_SUPPORTED = 0,
        NOT_PERFORMED = 1,
        PERFORMED = 2,
        RFU = 3
    };

    static inline void set_rrp(std::vector<uint8_t>& v, RRP_STATUS status) {
        v[4] &= 0xFC;
        v[4] |= static_cast<uint8_t>(status);
    };

    static inline RRP_STATUS get_rrp(const std::vector<uint8_t>& v) {
        return static_cast<RRP_STATUS>(v[4] & 0x03);
    };
};
static constexpr TAG_TVR_95 TVR_95{};

static constexpr char TERMINAL_CAPABILITIES_9F33_desc[] = "Terminal Capabilities";
struct TAG_TERMINAL_CAPABILITIES_9F33 : public tag_b {
    constexpr TAG_TERMINAL_CAPABILITIES_9F33() : tag_b(0x9F33, TERMINAL_CAPABILITIES_9F33_desc, 3, 3){};
    DECL_TAG_BIT(manual_key_entry, 1, 8);
    DECL_TAG_BIT(magnetic_stripe, 1, 7);
    DECL_TAG_BIT(icc_with_contacts, 1, 6);
    DECL_TAG_BIT(plaintext_pin_for_icc_verification, 2, 8);
    DECL_TAG_BIT(enciphered_pin_for_online_verification, 2, 7);
    DECL_TAG_BIT(signature, 2, 6);
    DECL_TAG_BIT(enciphered_pin_for_offline_verification, 2, 5);
    DECL_TAG_BIT(no_cvm_required, 2, 4);
    DECL_TAG_BIT(sda, 3, 8);
    DECL_TAG_BIT(dda, 3, 7);
    DECL_TAG_BIT(card_capture, 3, 6);
    DECL_TAG_BIT(cda, 3, 4);
    static constexpr std::array<const tag_bit_field*, 12> all_bits = {
        &manual_key_entry,
        &magnetic_stripe,
        &icc_with_contacts,
        &plaintext_pin_for_icc_verification,
        &enciphered_pin_for_online_verification,
        &signature,
        &enciphered_pin_for_offline_verification,
        &no_cvm_required,
        &sda,
        &dda,
        &card_capture,
        &cda};
};
static constexpr TAG_TERMINAL_CAPABILITIES_9F33 TERMINAL_CAPABILITIES_9F33{};

static constexpr char SECURITY_CAPABILITY_DF811F_desc[] = "Security Capablity";
struct TAG_SECURITY_CAPABILITY_DF811F : public tag_b {
    constexpr TAG_SECURITY_CAPABILITY_DF811F() : tag_b(0xDF811F, SECURITY_CAPABILITY_DF811F_desc, 1, 1){};
    DECL_TAG_BIT(sda, 1, 8);
    DECL_TAG_BIT(dda, 1, 7);
    DECL_TAG_BIT(card_capture, 1, 6);
    DECL_TAG_BIT(cda, 1, 4);
    static constexpr std::array<const tag_bit_field*, 4> all_bits = {
        &sda,
        &dda,
        &card_capture,
        &cda};
};
static constexpr TAG_SECURITY_CAPABILITY_DF811F SECURITY_CAPABILITY_DF811F{};

static constexpr char POST_GEN_AC_PUT_DATA_STATUS_DF810E_desc[] = "Post-Gen AC Put Data Status";
struct TAG_POST_GEN_AC_PUT_DATA_STATUS_DF810E : public tag_b {
    constexpr TAG_POST_GEN_AC_PUT_DATA_STATUS_DF810E() : tag_b(0xDF810E, POST_GEN_AC_PUT_DATA_STATUS_DF810E_desc, 1, 1){};
    DECL_TAG_BIT(completed, 1, 8);
    static constexpr std::array<const tag_bit_field*, 1> all_bits = {
        &completed};
};
static constexpr TAG_POST_GEN_AC_PUT_DATA_STATUS_DF810E POST_GEN_AC_PUT_DATA_STATUS_DF810E{};

static constexpr char PRE_GEN_AC_PUT_DATA_STATUS_DF810F_desc[] = "Pre-Gen AC Put Data Status";
struct TAG_PRE_GEN_AC_PUT_DATA_STATUS_DF810F : public tag_b {
    constexpr TAG_PRE_GEN_AC_PUT_DATA_STATUS_DF810F() : tag_b(0xDF810F, PRE_GEN_AC_PUT_DATA_STATUS_DF810F_desc, 1, 1){};
    DECL_TAG_BIT(completed, 1, 8);
    static constexpr std::array<const tag_bit_field*, 1> all_bits = {
        &completed};
};
static constexpr TAG_PRE_GEN_AC_PUT_DATA_STATUS_DF810F PRE_GEN_AC_PUT_DATA_STATUS_DF810F{};

static constexpr char POS_CARDHOLDER_INTERACTION_INFO_DF4B_desc[] = "POS Cardholder Interaction Information";
struct TAG_POS_CARDHOLDER_INTERACTION_INFO_DF4B : public tag_b {
    constexpr TAG_POS_CARDHOLDER_INTERACTION_INFO_DF4B() : tag_b(0xDF4B, POS_CARDHOLDER_INTERACTION_INFO_DF4B_desc, 3, 3){};
    DECL_TAG_BIT(od_cvm_verification_successful, 2, 5);
    DECL_TAG_BIT(context_is_conflicting, 2, 4);
    DECL_TAG_BIT(offline_change_pin_required, 2, 3);
    DECL_TAG_BIT(ack_required, 2, 2);
    DECL_TAG_BIT(od_cvm_required, 2, 1);
    DECL_TAG_BIT(wallet_requires_second_tap, 3, 1);
    static constexpr std::array<const tag_bit_field*, 6> all_bits = {
        &od_cvm_verification_successful,
        &context_is_conflicting,
        &offline_change_pin_required,
        &ack_required,
        &od_cvm_required,
        &wallet_requires_second_tap};
    static uint8_t get_version(const std::vector<uint8_t>& v) {
        return v[0];
    };
};
static constexpr TAG_POS_CARDHOLDER_INTERACTION_INFO_DF4B POS_CARDHOLDER_INTERACTION_INFO_DF4B{};

static constexpr char MOBILE_SUPPORT_INDICATOR_9F7E_desc[] = "Mobile Support Indicator";
struct TAG_MOBILE_SUPPORT_INDICATOR_9F7E : public tag_b {
    constexpr TAG_MOBILE_SUPPORT_INDICATOR_9F7E() : tag_b(0x9F7E, MOBILE_SUPPORT_INDICATOR_9F7E_desc, 1, 1){};
    DECL_TAG_BIT(od_cvm_required, 1, 2);
    DECL_TAG_BIT(mobile_supported, 1, 1);
    static constexpr std::array<const tag_bit_field*, 2> all_bits = {
        &od_cvm_required,
        &mobile_supported};
};
static constexpr TAG_MOBILE_SUPPORT_INDICATOR_9F7E MOBILE_SUPPORT_INDICATOR_9F7E{};

static constexpr char KERNEL_CONFIGURATION_DF811B_desc[] = "Kernel Configuration";
struct TAG_KERNEL_CONFIGURATION_DF811B : public tag_b {
    constexpr TAG_KERNEL_CONFIGURATION_DF811B() : tag_b(0xDF811B, KERNEL_CONFIGURATION_DF811B_desc, 1, 1){};
    DECL_TAG_BIT(magstripe_mode_contactless_not_supported, 1, 8);
    DECL_TAG_BIT(emv_mode_contactless_not_supported, 1, 7);
    DECL_TAG_BIT(on_device_verification_supported, 1, 6);
    DECL_TAG_BIT(rrp_supported, 1, 5);
    static constexpr std::array<const tag_bit_field*, 4> all_bits = {
        &magstripe_mode_contactless_not_supported,
        &emv_mode_contactless_not_supported,
        &on_device_verification_supported,
        &rrp_supported};
};
static constexpr TAG_KERNEL_CONFIGURATION_DF811B KERNEL_CONFIGURATION_DF811B{};

static constexpr char MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E_desc[] = "Mag-stripe CVM Capability CVM Required";
struct TAG_MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E : public tag_b {
    constexpr TAG_MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E() : tag_b(0xDF811E, MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E_desc, 1, 1){};
    static OUTCOME_CVM custom_value(const std::vector<uint8_t>& v) {
        switch (v[0] >> 4) {
        case 0:
            return OUTCOME_CVM::NO_CVM;
        case 1:
            return OUTCOME_CVM::SIGNATURE;
        case 2:
            return OUTCOME_CVM::ONLINE_PIN;
        case 3:
        default:
            return OUTCOME_CVM::NA;
        };
    };
};
static constexpr TAG_MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E{};

static constexpr char MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C_desc[] = "Mag-stripe CVM Capability No CVM Required";
struct TAG_MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C : public tag_b {
    constexpr TAG_MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C() : tag_b(0xDF812C, MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C_desc, 1, 1){};
    static OUTCOME_CVM custom_value(const std::vector<uint8_t>& v) {
        switch (v[0] >> 4) {
        case 0:
            return OUTCOME_CVM::NO_CVM;
        case 1:
            return OUTCOME_CVM::SIGNATURE;
        case 2:
            return OUTCOME_CVM::ONLINE_PIN;
        case 3:
        default:
            return OUTCOME_CVM::NA;
        };
    };
};
static constexpr TAG_MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C{};

static constexpr char CVM_CAPABILITY_CVM_REQUIRED_DF8118_desc[] = "CVM Capability – CVM Required";
struct TAG_CVM_CAPABILITY_CVM_REQUIRED_DF8118 : public tag_b {
    constexpr TAG_CVM_CAPABILITY_CVM_REQUIRED_DF8118() : tag_b(0xDF8118, CVM_CAPABILITY_CVM_REQUIRED_DF8118_desc, 1, 1){};
    DECL_TAG_BIT(plaintext_pin_for_icc_verification, 1, 8);
    DECL_TAG_BIT(enciphered_pin_for_online_verification, 1, 7);
    DECL_TAG_BIT(signature, 1, 6);
    DECL_TAG_BIT(enciphered_pin_for_offline_verification, 1, 5);
    DECL_TAG_BIT(no_cvm_required, 1, 4);
    static constexpr std::array<const tag_bit_field*, 5> all_bits = {
        &plaintext_pin_for_icc_verification,
        &enciphered_pin_for_online_verification,
        &signature,
        &enciphered_pin_for_offline_verification,
        &no_cvm_required};
};
static constexpr TAG_CVM_CAPABILITY_CVM_REQUIRED_DF8118 CVM_CAPABILITY_CVM_REQUIRED_DF8118{};

static constexpr char CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119_desc[] = "CVM Capability – No CVM Required";
struct TAG_CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119 : public tag_b {
    constexpr TAG_CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119() : tag_b(0xDF8119, CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119_desc, 1, 1){};
    DECL_TAG_BIT(plaintext_pin_for_icc_verification, 1, 8);
    DECL_TAG_BIT(enciphered_pin_for_online_verification, 1, 7);
    DECL_TAG_BIT(signature, 1, 6);
    DECL_TAG_BIT(enciphered_pin_for_offline_verification, 1, 5);
    DECL_TAG_BIT(no_cvm_required, 1, 4);
    static constexpr std::array<const tag_bit_field*, 5> all_bits = {
        &plaintext_pin_for_icc_verification,
        &enciphered_pin_for_online_verification,
        &signature,
        &enciphered_pin_for_offline_verification,
        &no_cvm_required};
};
static constexpr TAG_CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119 CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119{};

static constexpr char CARD_DATA_INPUT_CAPABILITY_DF8117_desc[] = "Card Data Input Capability";
struct TAG_CARD_DATA_INPUT_CAPABILITY_DF8117 : public tag_b {
    constexpr TAG_CARD_DATA_INPUT_CAPABILITY_DF8117() : tag_b(0xDF8117, CARD_DATA_INPUT_CAPABILITY_DF8117_desc, 1, 1){};
    DECL_TAG_BIT(manual_key_input, 1, 8);
    DECL_TAG_BIT(magnetic_stripe, 1, 7);
    DECL_TAG_BIT(icc_with_contacts, 1, 6);
    static constexpr std::array<const tag_bit_field*, 3> all_bits = {
        &manual_key_input,
        &magnetic_stripe,
        &icc_with_contacts};
};
static constexpr TAG_CARD_DATA_INPUT_CAPABILITY_DF8117 CARD_DATA_INPUT_CAPABILITY_DF8117{};

static constexpr char TTQ_9F66_desc[] = "Terminal Transaction Qualifiers";
struct TAG_TTQ_9F66 : public tag_b {
    constexpr TAG_TTQ_9F66() : tag_b(0x9F66, TTQ_9F66_desc, 4, 4){};
    DECL_TAG_BIT(offline_data_auth_for_online_authorization_supported, 1, 1);
    DECL_TAG_BIT(signature_supported, 1, 2);
    DECL_TAG_BIT(online_pin_supported, 1, 3);
    DECL_TAG_BIT(offline_only_reader, 1, 4);
    DECL_TAG_BIT(emv_contact_chip_supported, 1, 5);
    DECL_TAG_BIT(emv_mode_supported, 1, 6);
    DECL_TAG_BIT(magstripe_mode_supported, 1, 8);
    DECL_TAG_BIT(offline_pin_supported, 2, 6);
    DECL_TAG_BIT(cvm_required, 2, 7);
    DECL_TAG_BIT(online_cryptogram_required, 2, 8);
    DECL_TAG_BIT(consumer_device_cvm_supported, 3, 7);
    DECL_TAG_BIT(issuer_update_processing_supported, 3, 8);

    static constexpr std::array<const tag_bit_field*, 12> all_bits = {
        &offline_data_auth_for_online_authorization_supported,
        &signature_supported,
        &online_pin_supported,
        &offline_only_reader,
        &emv_contact_chip_supported,
        &emv_mode_supported,
        &magstripe_mode_supported,
        &offline_pin_supported,
        &cvm_required,
        &online_cryptogram_required,
        &consumer_device_cvm_supported,
        &issuer_update_processing_supported};
};
static constexpr TAG_TTQ_9F66 TTQ_9F66{};

static constexpr char ADDITIONAL_TERMINAL_CAPABILITIES_9F40_desc[] = "Additional Terminal Capabilities";
struct TAG_ADDITIONAL_TERMINAL_CAPABILITIES_9F40 : public tag_b {
    constexpr TAG_ADDITIONAL_TERMINAL_CAPABILITIES_9F40() : tag_b{0x9F40, ADDITIONAL_TERMINAL_CAPABILITIES_9F40_desc, 5, 5} {};
    DECL_TAG_BIT(cash, 1, 8);
    DECL_TAG_BIT(goods, 1, 7);
    DECL_TAG_BIT(services, 1, 6);
    DECL_TAG_BIT(cashback, 1, 5);
    DECL_TAG_BIT(inquiry, 1, 4);
    DECL_TAG_BIT(transfer, 1, 3);
    DECL_TAG_BIT(payment, 1, 2);
    DECL_TAG_BIT(administrative, 1, 1);
    DECL_TAG_BIT(cash_deposit, 2, 8);
    DECL_TAG_BIT(numeric_keys, 3, 8);
    DECL_TAG_BIT(alphetical_and_special_keys, 3, 7);
    DECL_TAG_BIT(command_keys, 3, 6);
    DECL_TAG_BIT(function_keys, 3, 5);
    DECL_TAG_BIT(print_attendant, 4, 8);
    DECL_TAG_BIT(print_cardholder, 4, 7);
    DECL_TAG_BIT(display_attendant, 4, 6);
    DECL_TAG_BIT(display_cardholder, 4, 5);
    DECL_TAG_BIT(code_table_10, 4, 2);
    DECL_TAG_BIT(code_table_9, 4, 1);
    DECL_TAG_BIT(code_table_8, 5, 8);
    DECL_TAG_BIT(code_table_7, 5, 7);
    DECL_TAG_BIT(code_table_6, 5, 6);
    DECL_TAG_BIT(code_table_5, 5, 5);
    DECL_TAG_BIT(code_table_4, 5, 4);
    DECL_TAG_BIT(code_table_3, 5, 3);
    DECL_TAG_BIT(code_table_2, 5, 2);
    DECL_TAG_BIT(code_table_1, 5, 1);
    static constexpr std::array<const tag_bit_field*, 27> all_bits = {
        &cash,
        &goods,
        &services,
        &cashback,
        &inquiry,
        &transfer,
        &payment,
        &administrative,
        &cash_deposit,
        &numeric_keys,
        &alphetical_and_special_keys,
        &command_keys,
        &function_keys,
        &print_attendant,
        &print_cardholder,
        &display_attendant,
        &display_cardholder,
        &code_table_10,
        &code_table_9,
        &code_table_8,
        &code_table_7,
        &code_table_6,
        &code_table_5,
        &code_table_4,
        &code_table_3,
        &code_table_2,
        &code_table_1};
};
static constexpr TAG_ADDITIONAL_TERMINAL_CAPABILITIES_9F40 ADDITIONAL_TERMINAL_CAPABILITIES_9F40{};

static constexpr char CAP_9F68_desc[] = "Card Additional Processes (CAP)";
struct TAG_CAP_9F68 : public tag_b {
    constexpr TAG_CAP_9F68() : tag_b(0x9F68, CAP_9F68_desc, 4, 4){};
    DECL_TAG_BIT(low_value_check_supported, 1, 8);
    DECL_TAG_BIT(low_value_and_ctta_check_supported, 1, 7);
    DECL_TAG_BIT(count_qvsdc_online_transactions, 1, 6);
    DECL_TAG_BIT(streamlined_qvsdc_supported, 1, 5);
    DECL_TAG_BIT(pin_retries_exceeded_check_supported, 1, 4);
    DECL_TAG_BIT(offline_international_transactions_allowed, 1, 3);
    DECL_TAG_BIT(card_prefers_contact_chip, 1, 2);
    DECL_TAG_BIT(return_aosa, 1, 1);
    DECL_TAG_BIT(include_country_code_in_determination, 2, 8);
    DECL_TAG_BIT(international_transaction_not_allowed, 2, 7);
    DECL_TAG_BIT(disable_oda_for_online_authorization, 2, 6);
    DECL_TAG_BIT(issuer_update_supported, 2, 5);
    DECL_TAG_BIT(do_not_count_qvsdc_offline_transactions, 2, 4);
    DECL_TAG_BIT(card_prefer_online, 2, 3);
    DECL_TAG_BIT(online_pin_supported_for_domestic_transactions, 3, 8);
    DECL_TAG_BIT(online_pin_supported_for_international_transactions, 3, 7);
    DECL_TAG_BIT(off_line_supported, 3, 6);
    DECL_TAG_BIT(signature_supported, 3, 5);
    DECL_TAG_BIT(cdcvm_supported, 3, 4);
    static constexpr std::array<const tag_bit_field*, 19> all_bits = {
        &low_value_check_supported,
        &low_value_and_ctta_check_supported,
        &count_qvsdc_online_transactions,
        &streamlined_qvsdc_supported,
        &pin_retries_exceeded_check_supported,
        &offline_international_transactions_allowed,
        &card_prefers_contact_chip,
        &return_aosa,
        &include_country_code_in_determination,
        &international_transaction_not_allowed,
        &disable_oda_for_online_authorization,
        &issuer_update_supported,
        &do_not_count_qvsdc_offline_transactions,
        &card_prefer_online,
        &online_pin_supported_for_domestic_transactions,
        &online_pin_supported_for_international_transactions,
        &off_line_supported,
        &signature_supported,
        &cdcvm_supported};
};
static constexpr TAG_CAP_9F68 CAP_9F68{};

static constexpr char AUC_9F07_desc[] = "Application Usage Control (AUC)";
struct TAG_AUC_9F07 : public tag_b {
    constexpr TAG_AUC_9F07() : tag_b(0x9F07, AUC_9F07_desc, 2, 2, PERM_K | PERM_RA){};
    DECL_TAG_BIT(valid_for_domestic_cash, 1, 8);
    DECL_TAG_BIT(valid_for_international_cash, 1, 7);
    DECL_TAG_BIT(valid_for_domestic_goods, 1, 6);
    DECL_TAG_BIT(valid_for_international_goods, 1, 5);
    DECL_TAG_BIT(valid_for_domestic_services, 1, 4);
    DECL_TAG_BIT(valid_for_international_services, 1, 3);
    DECL_TAG_BIT(valid_at_atm, 1, 2);
    DECL_TAG_BIT(valid_other_than_atm, 1, 1);
    DECL_TAG_BIT(domestic_cashback_allowed, 2, 8);
    DECL_TAG_BIT(international_cashback_allowed, 2, 7);
    static constexpr std::array<const tag_bit_field*, 10> all_bits = {
        &valid_for_domestic_cash,
        &valid_for_international_cash,
        &valid_for_domestic_goods,
        &valid_for_international_goods,
        &valid_for_domestic_services,
        &valid_for_international_services,
        &valid_at_atm,
        &valid_other_than_atm,
        &domestic_cashback_allowed,
        &international_cashback_allowed};
};
static constexpr TAG_AUC_9F07 AUC_9F07{};

static constexpr char CA_PUBLIC_KEY_INDEX_8F_desc[] = "Certificate Authority Public Key Index (PKI)";
struct TAG_CA_PUBLIC_KEY_INDEX_8F : public tag_b {
    constexpr TAG_CA_PUBLIC_KEY_INDEX_8F() : tag_b(0x8F, CA_PUBLIC_KEY_INDEX_8F_desc, 1, 1,
                                                   PERM_K | PERM_RA){};
    static uint8_t custom_value(const std::vector<uint8_t>& value) {
        return value[0];
    };
};
static constexpr TAG_CA_PUBLIC_KEY_INDEX_8F CA_PUBLIC_KEY_INDEX_8F{};

static constexpr char AIP_82_desc[] = "Application Interchange Profile";
struct TAG_AIP_82 : public tag_b {
    constexpr TAG_AIP_82() : tag_b(0x82, AIP_82_desc, 2, 2, PERM_K | PERM_RA){};
    DECL_TAG_BIT(sda_supported_for_online_auth, 1, 7);
    DECL_TAG_BIT(dda_supported, 1, 6);
    DECL_TAG_BIT(cardholder_verification_supported, 1, 5);
    DECL_TAG_BIT(terminal_risk_management_to_be_performed, 1, 4);
    DECL_TAG_BIT(issuer_authentication_is_supported, 1, 3);
    DECL_TAG_BIT(on_device_cardholder_verification_supported, 1, 2);
    DECL_TAG_BIT(cda_supported, 1, 1);

    // used as in kernel 3
    DECL_TAG_BIT(magstripe_mode_supported, 2, 8);

    // used as in kernel 2
    DECL_TAG_BIT(emv_mode_supported, 2, 8);
    DECL_TAG_BIT(mobile_phone, 2, 7);
    DECL_TAG_BIT(contactless_transaction, 2, 6);
    DECL_TAG_BIT(rrp_supported, 2, 1);
    static constexpr std::array<const tag_bit_field*, 12> all_bits = {
        &sda_supported_for_online_auth,
        &dda_supported,
        &cardholder_verification_supported,
        &terminal_risk_management_to_be_performed,
        &issuer_authentication_is_supported,
        &on_device_cardholder_verification_supported,
        &cda_supported,
        &magstripe_mode_supported,
        &emv_mode_supported,
        &mobile_phone,
        &contactless_transaction,
        &rrp_supported};
};
static constexpr TAG_AIP_82 AIP_82{};

static constexpr char CTQ_9F6C_desc[] = "Card Transaction Qualifiers (CTQ)";
struct TAG_CTQ_9F6C : public tag_b {
    constexpr TAG_CTQ_9F6C() : tag_b(0x9F6C, CTQ_9F6C_desc, 2, 2){};
    DECL_TAG_BIT(online_pin_required, 1, 8);
    DECL_TAG_BIT(signature_required, 1, 7);
    DECL_TAG_BIT(online_if_oda_fail_and_reader_online_capable, 1, 6);
    DECL_TAG_BIT(switch_intf_if_oda_fail_and_reader_support_contact, 1, 5);
    DECL_TAG_BIT(online_if_application_expired, 1, 4);
    DECL_TAG_BIT(switch_intf_for_cash, 1, 3);
    DECL_TAG_BIT(switch_intf_for_cashback, 1, 2);
    DECL_TAG_BIT(consumer_device_cmv_performed, 2, 8);
    DECL_TAG_BIT(card_support_issuer_update, 2, 7);
    static constexpr std::array<const tag_bit_field*, 9> all_bits = {
        &online_pin_required,
        &signature_required,
        &online_if_oda_fail_and_reader_online_capable,
        &switch_intf_if_oda_fail_and_reader_support_contact,
        &online_if_application_expired,
        &switch_intf_for_cash,
        &switch_intf_for_cashback,
        &consumer_device_cmv_performed,
        &card_support_issuer_update};
};
static constexpr TAG_CTQ_9F6C CTQ_9F6C{};

static constexpr char TRACK1_DATA_56_desc[] = "Track 1 Data";
struct TAG_TRACK1_DATA_56 : public tag_ans {
    constexpr TAG_TRACK1_DATA_56() : tag_ans(0x56, TRACK1_DATA_56_desc, 0, 76, PERM_K | PERM_RA){};
    struct track_data {
        std::vector<uint8_t> pan;
        std::vector<uint8_t> name;
        std::vector<uint8_t> date;
        std::vector<uint8_t> service_code;
        std::vector<uint8_t> discretionary_data;
    };

    static std::vector<uint8_t> serialize(const track_data& data) {
        std::vector<uint8_t> ret{};
        ret.push_back(0x42);
        std::copy(data.pan.begin(), data.pan.end(), back_inserter(ret));
        ret.push_back(0x5E);
        std::copy(data.name.begin(), data.name.end(), back_inserter(ret));
        ret.push_back(0x5E);
        std::copy(data.date.begin(), data.date.end(), back_inserter(ret));
        std::copy(data.service_code.begin(), data.service_code.end(), back_inserter(ret));
        std::copy(data.discretionary_data.begin(), data.discretionary_data.end(),
		back_inserter(ret));
	
        return ret;
    };

    static bool parse(const std::vector<uint8_t>& v, struct track_data& data) {
        pr_debug("deserialize TRACK1_DATA_56 : ", v, "\n");
        auto p = v.begin();
        bool ret = false;
        while (true) {
            if (p == v.end() || *p != 0x42)
                break;
            ++p;
            while (p != v.end() && *p != 0x5E) {
                data.pan.push_back(*p);
                ++p;
            }
            if (*p != 0x5E)
                break;
            ++p;

            while (p != v.end() && *p != 0x5E) {
                data.name.push_back(*p);
                ++p;
            }
            if (*p != 0x5E)
                break;
            ++p;

            if (p + 4 >= v.end())
                break;
            data.date = std::vector<uint8_t>{p, p + 4};
            p += 4;

            if (p + 3 > v.end())
                break;
            data.service_code = std::vector<uint8_t>{p, p + 3};
            p += 3;

            data.discretionary_data = std::vector<uint8_t>{p, v.end()};

            ret = true;
            break;
        }

        return ret;
    };

    static struct track_data custom_value(const std::vector<uint8_t>& v) {
        struct track_data data {};
        if (parse(v, data)) {
            return data;
        } else {
            return track_data{};
        };
    };
};
static constexpr TAG_TRACK1_DATA_56 TRACK1_DATA_56{};

struct TRACK2_COMMON {
    struct track_data {
        std::string pan;
        std::string date;
        std::string service_code;
        std::string discretionary_data;
    };

    static uint8_t __get_nibble(const std::vector<uint8_t>& v, unsigned int n) {
        int index = n >> 1;
        if (n % 2) {
            return v[index] & 0x0F;
        }

        return v[index] >> 4;
    };

    static void __set_nibble(std::vector<uint8_t>& v, unsigned int n, uint8_t val) {
        int index = n >> 1;
        if (n % 2) {
            v[index] &= 0xF0;
            v[index] |= val;
        } else {
            v[index] &= 0x0F;
            v[index] |= (val << 4);
        };
    };

    static std::vector<uint8_t> serialize(struct track_data& data) {
        std::vector<uint8_t> v{};
        int nibbles = data.pan.size() + 1 + 4 + 3 + data.discretionary_data.size() + 1;
        v.resize(nibbles / 2);
        int n = 0;

        for (auto c : data.pan) {
            __set_nibble(v, n++, c - '0');
        };

        __set_nibble(v, n++, 0x0D);
        for (auto c : data.date) {
            __set_nibble(v, n++, c - '0');
        }

        for (auto c : data.service_code) {
            __set_nibble(v, n++, c - '0');
        }

        for (auto c : data.discretionary_data) {
            __set_nibble(v, n++, c - '0');
        }

        if (n % 2) {
            __set_nibble(v, n, 0x0F);
        }

        return v;
    };

    static bool parse(const std::vector<uint8_t>& v, struct track_data& data) {
        int n;
        int nibbles = v.size() * 2;
        for (n = 0; n != nibbles; n++) {
            char d = __get_nibble(v, n);
            if (d == 0x0D)
                break;
            d += '0';
            data.pan.push_back(d);
        }

        if (n++ >= nibbles)
            return false;

        for (int i = 0; i != 4; i++, n++) {
            if (n >= nibbles)
                return false;
            char d = __get_nibble(v, n) + '0';
            data.date.push_back(d);
        };

        for (int i = 0; i != 3; i++, n++) {
            if (n >= nibbles)
                return false;
            char d = __get_nibble(v, n) + '0';
            data.service_code.push_back(d);
        }

        while (n < nibbles) {
            uint8_t c = __get_nibble(v, n);
            if (c == 0x0F)
                break;
            char d = c + '0';
            data.discretionary_data.push_back(d);
            n++;
        }

        return true;
    };

    static std::vector<uint8_t> discretionary_data_to_bytes(const std::string& dd) {
        std::vector<uint8_t> ret{};
        for (auto p = dd.begin();;) {
            uint8_t b;
            if (p == dd.end())
                break;
            b = (*p - '0') << 4;
            ++p;

            if (p == dd.end()) {
                b |= 0x0F;
            } else {
                b |= (*p - '0');
                ++p;
            }

            ret.push_back(b);
        }

        return ret;
    };
};

static constexpr char TRACK2_DATA_9F6B_desc[] = "Track 2 Data";
struct TAG_TRACK2_DATA_9F6B : public tag_b, TRACK2_COMMON {
    constexpr TAG_TRACK2_DATA_9F6B() : tag_b(0x9F6B, TRACK2_DATA_9F6B_desc, 0, 19, PERM_K | PERM_RA){};
};
static constexpr TAG_TRACK2_DATA_9F6B TRACK2_DATA_9F6B{};

static constexpr char TRACK2_57_desc[] = "Track 2 Equivalent Data";
struct TAG_TRACK2_57 : public tag_b, TRACK2_COMMON {
    constexpr TAG_TRACK2_57() : tag_b(0x57, TRACK2_57_desc, 0, 19, PERM_K | PERM_RA){};

    static std::string get_pan(const std::vector<uint8_t>& v) {
        struct track_data data {};
        parse(v, data);
        return data.pan;
    };

    static void set_dd(std::vector<uint8_t>& v, const std::string& dd) {
        struct track_data data {};
        parse(v, data);
        data.discretionary_data = dd;
        v = serialize(data);
    }
};
static constexpr TAG_TRACK2_57 TRACK2_57{};

static constexpr char ISSUER_APPLICATION_DATA_9F10_desc[] = "Issuer Application Data";
struct TAG_ISSUER_APPLICATION_DATA_9F10 : public tag_b {
    constexpr TAG_ISSUER_APPLICATION_DATA_9F10() : tag_b(0x9F10, ISSUER_APPLICATION_DATA_9F10_desc, 0, 32,
                                                         PERM_K | PERM_RA){};
    static AC_TYPE custom_value(const std::vector<uint8_t>& v) {
        return narrow_cast<AC_TYPE>((v[4] >> 4) & 3);
    };
};
static constexpr TAG_ISSUER_APPLICATION_DATA_9F10 ISSUER_APPLICATION_DATA_9F10{};

static constexpr char CID_9F27_desc[] = "Cryptogram Information Data";
struct TAG_CID_9F27 : public tag_b {
    constexpr TAG_CID_9F27() : tag_b(0x9F27, CID_9F27_desc, 1, 1, PERM_K | PERM_RA){};
    static AC_TYPE custom_value(const std::vector<uint8_t>& value) {
        return narrow_cast<AC_TYPE>((value[0] >> 6) & 0x03);
    };

    static void set_type(std::vector<uint8_t>& value, AC_TYPE type) {
        uint8_t b = static_cast<uint8_t>(type);
        value[0] &= ~0xC0;
        value[0] |= (b << 6);
    };
};
static constexpr TAG_CID_9F27 CID_9F27{};

static constexpr char AFL_94_desc[] = "Application File Locator (AFL)";
struct TAG_AFL_94 : public tag_var {
    constexpr TAG_AFL_94() : tag_var(0x94, AFL_94_desc, 0, 252, PERM_K | PERM_RA){};
    static constexpr int unit_size = 4;
    static uint8_t get_sfi(const uint8_t* rec) {
        return (rec[0] >> 3) & 0x1F;
    };

    static uint8_t get_first_record(const uint8_t* rec) {
        return rec[1];
    };

    static uint8_t get_last_record(const uint8_t* rec) {
        return rec[2];
    };

    static uint8_t get_oda_records(const uint8_t* rec) {
        return rec[3];
    };

    virtual bool validate(const std::vector<uint8_t>& v) const override {
        int size = v.size();
        if (size == 0 || size % 4 != 0)
            return false;
        for (auto ptr = v.data(); size > 0; ptr += 4, size -= 4) {
            auto sfi = get_sfi(ptr);
            auto first = get_first_record(ptr);
            auto last = get_last_record(ptr);
            auto oda_num = get_oda_records(ptr);
            if (sfi == 0 || sfi == 31 || first == 0 || last < first || oda_num > last - first + 1) {
                return false;
            }
        };
        return true;
    }
};
static constexpr TAG_AFL_94 AFL_94{};

static constexpr char ADF_NAME_4F_desc[] = "Application Identifier (ADF Name)";
struct TAG_ADF_NAME_4F : public tag_b {
    constexpr TAG_ADF_NAME_4F() : tag_b(0x4F, ADF_NAME_4F_desc, 5, 16){};
    virtual bool validate(const std::vector<uint8_t>& value) const override {
        if (!tag_b::validate(value))
            return false;

        // EMV 4.3. Book 1 12.2.1
        // TODO check first 5 bytes start with RID
        return true;
    };
};
static constexpr TAG_ADF_NAME_4F ADF_NAME_4F{};

// Kernel Identifier length could be either 1 or 3-8 according to spec (Table A1 Book B)
static constexpr char KERNEL_IDENTIFIER_9F2A_desc[] = "Kernel Identifier - Card";
struct TAG_KERNEL_IDENTIFIER_9F2A : public tag_b {
    constexpr TAG_KERNEL_IDENTIFIER_9F2A() : tag_b(0x9F2A, KERNEL_IDENTIFIER_9F2A_desc, 1, 8){};

    static bool get_kid(const std::vector<uint8_t>& value, uint32_t& kid) {
        auto flags = value[0] >> 6;

        // 3.3.2.5 Book B for Kernel ID selection
        if (flags == 0 || flags == 1) {
            kid = static_cast<uint32_t>(value[0]);
        } else if ((value.size() >= 3) && ((value[0] & 0x3F) != 0)) {
            kid = (value[0] << 16) | (value[1] << 8) | value[2];
        } else {
            return false;
        }

        return true;
    }
};
static constexpr TAG_KERNEL_IDENTIFIER_9F2A KERNEL_IDENTIFIER_9F2A{};

static constexpr char APPLICATION_PRIORITY_INDICATOR_desc[] = "Application Priority Indicator";
struct TAG_APPLICATION_PRIORITY_INDICATOR_87 : public tag_b {
    constexpr TAG_APPLICATION_PRIORITY_INDICATOR_87() : tag_b(0x87, APPLICATION_PRIORITY_INDICATOR_desc, 1, 1, PERM_K | PERM_RA){};
    static uint8_t custom_value(const std::vector<uint8_t>& value) {
        return value[0] & 0x0F;
    };
};
static constexpr TAG_APPLICATION_PRIORITY_INDICATOR_87 APPLICATION_PRIORITY_INDICATOR_87{};

class tlv_db;
static constexpr char TRANSACTION_TYPE_desc[] = "Transaction Type";
struct TAG_TRANSACTION_TYPE_9C : public tag_n {
    constexpr TAG_TRANSACTION_TYPE_9C() : tag_n(0x9C, TRANSACTION_TYPE_desc, 2, 2, PERM_K | PERM_ACT | PERM_DET){};
    enum class ENUMS : uint8_t {
        PURCHASE = 0,
        CASH = 1,
        ADJUSTMENT = 2,
        PURCHASE_WITH_CASHBACK = 9,
        REFUND = 20,
        CASH_DISBURSEMENT = 17,
        BALANCE_INQUIRY = 31
    };

    static ENUMS custom_value(const std::vector<uint8_t>& v) {
        auto nv = to_numeric_value(v);
        return narrow_cast<ENUMS>(nv);
    };
};
static constexpr TAG_TRANSACTION_TYPE_9C TRANSACTION_TYPE_9C{};

using TRANSACTION_TYPE = TAG_TRANSACTION_TYPE_9C::ENUMS;

static constexpr char TERMINAL_TYPE_9F35_desc[] = "Terminal Type";
struct TAG_TERMINAL_TYPE_9F35 : public tag_n {
    constexpr TAG_TERMINAL_TYPE_9F35() : tag_n(0x9F35, TERMINAL_TYPE_9F35_desc, 2, 2, PERM_K | PERM_ACT | PERM_DET){};
    static inline bool is_attended(const std::vector<uint8_t>& v) {
        auto p = v[0] & 0x0F;
        return (p < 4); // 1, 2, 3 for attended
    };

    static inline bool is_unattended(const std::vector<uint8_t>& v) {
        return !is_attended(v);
    };
};
static constexpr TAG_TERMINAL_TYPE_9F35 TERMINAL_TYPE_9F35{};

static constexpr char AMOUNT_AUTHORISED_desc[] = "Amount, Authorised (Numeric)";
struct TAG_AMOUNT_AUTHORISED_9F02 : public tag_n {
    constexpr TAG_AMOUNT_AUTHORISED_9F02() : tag_n(0x9F02, AMOUNT_AUTHORISED_desc, 12, 12,
                                                   PERM_K | PERM_ACT | PERM_DET){};
    static bool is_single_unit_currency(numeric_value_type v) {
        return v == 100;
    }
};
static constexpr TAG_AMOUNT_AUTHORISED_9F02 AMOUNT_AUTHORISED_9F02{};

namespace KERNEL2 {
DECL_TAG_B(UDOL_9F69, "UDOL", 0x9F69, 0, 250, PERM_K | PERM_RA);
DECL_TAG_B(PUNATC_TRACK2_9F66, "PUNATC(Track2)", 0x9F66, 2, 2, PERM_K | PERM_RA);

static constexpr char APPLICATION_CAPABILITIES_INFO_9F5D_desc[] = "Application Capabilities Information";
struct TAG_APPLICATION_CAPABILITIES_INFO_9F5D : public tag_b {
    constexpr TAG_APPLICATION_CAPABILITIES_INFO_9F5D() : tag_b(0x9F5D, APPLICATION_CAPABILITIES_INFO_9F5D_desc, 3, 3, PERM_K | PERM_RA){};
    static inline int get_aci_version(const std::vector<uint8_t>& v) {
        return v[0] >> 4;
    };

    static inline int get_ds_version(const std::vector<uint8_t>& v) {
        return v[0] & 0x0F;
    };

    static inline uint8_t get_sdc_scheme_indicator(const std::vector<uint8_t>& v) {
        return v[2];
    };

    DECL_TAG_BIT(support_for_field_off_detection, 2, 3);
    DECL_TAG_BIT(support_for_balance_reading, 2, 2);
    DECL_TAG_BIT(cda_supported_over_tc_arqc_aac, 2, 1);

    static constexpr std::array<const tag_bit_field*, 3> all_bits = {
        &support_for_field_off_detection,
        &support_for_balance_reading,
        &cda_supported_over_tc_arqc_aac};
};
static constexpr TAG_APPLICATION_CAPABILITIES_INFO_9F5D APPLICATION_CAPABILITIES_INFO_9F5D{};

}; // namespace KERNEL2

struct KERNEL2_NS {
    static inline const tag_sets all_tags_set{
        &APPLICATION_LABEL_50,
        &TRACK1_DATA_56,
        &TRACK2_57,
        &PAN_5A,
        &APPLICATION_EXPIRE_DATE_5F24,
        &APPLICATION_EFFECTIVE_DATE_5F25,
        &ISSUER_COUNTRY_CODE_5F28,
        &TRANSACTION_CURRENCY_CODE_5F2A,
        &LANG_PREF_5F2D,
        &SERVICE_CODE_5F30,
        &PAN_SEQ_5F34,
        &TRANSACTION_CURRENCY_EXPONENT_5F36,
        &ACCOUNT_TYPE_5F57,
        &FCI_TEMPLATE_6F,
        &READ_RECORD_RESPONSE_TEMPLATE_70,
        &RESPONSE_TEMPLATE_FORMAT_2_77,
        &RESPONSE_TEMPLATE_FORMAT_1_80,
        &AIP_82,
        &DF_NAME_84,
        &APPLICATION_PRIORITY_INDICATOR_87,
        &CDOL1_8C,
        &CVM_LIST_8E,
        &CA_PUBLIC_KEY_INDEX_8F,
        &ISSUER_PUB_KEY_CERT_90,
        &ISSUER_PUB_KEY_REMAINER_92,
        &SIGNED_STATIC_APPLICATION_DATA_93,
        &AFL_94,
        &TVR_95,
        &TRANSACTION_DATE_9A,
        &TRANSACTION_TYPE_9C,
        &ACQUIRER_IDENTIFIER_9F01,
        &AMOUNT_AUTHORISED_9F02,
        &AMOUNT_OTHER_9F03,
        &AUC_9F07,
        &APPLICATION_VERSION_NUMBER_CARD_9F08,
        &APPLICATION_VERSION_NUMBER_READER_9F09,
        &IAC_DEFAULT_9F0D,
        &IAC_DENIAL_9F0E,
        &IAC_ONLINE_9F0F,
        &ISSUER_APPLICATION_DATA_9F10,
        &ISSUER_CODE_TABLE_INDEX_9F11,
        &APP_PREFERRED_NAME_9F12,
        &MERCHANT_CATEGORY_CODE_9F15,
        &MERCHANT_IDENTIFIER_9F16,
        &TERMINAL_COUNTRY_CODE_9F1A,
        &TERMINAL_IDENTIFICATION_9F1C,
        &TERMINAL_RISK_MANAGEMENT_DATA_9F1D,
        &INTERFACE_DEVICE_SERIAL_NUMBER_9F1E,
        &TRACK1_DISCRETIONARY_DATA_9F1F,
        &TRACK2_DISCRETIONARY_DATA_9F20,
        &TRANSACTION_TIME_9F21,
        &APPLICATION_CRYPTOGRAM_9F26,
        &CID_9F27,
        &ISSUER_PUB_KEY_EXP_9F32,
        &TERMINAL_CAPABILITIES_9F33,
        &CVM_RESULT_9F34,
        &TERMINAL_TYPE_9F35,
        &ATC_9F36,
        &UNPREDICTABLE_NUMBER_9F37,
        &PDOL_9F38,
        &ADDITIONAL_TERMINAL_CAPABILITIES_9F40,
        &APPLICATION_CURRENCY_CODE_9F42,
        &APPLICATION_CURRENCY_EXPONENT_9F44,
        &ICC_PUB_KEY_CERT_9F46,
        &ICC_PUB_KEY_EXP_9F47,
        &ICC_PUB_KEY_REMAINER_9F48,
        &SDA_TAG_LIST_9F4A,
        &SDAD_9F4B,
        &ICC_DYNAMIC_NUMBER_9F4C,
        &LOG_ENTRY_9F4D,
        &MERCHANT_NAME_AND_LOCATION_9F4E,
        &OFFLINE_ACCUMULATOR_BALANCE_9F50,
        &DRDOL_9F51,
        &TRANSACTION_CATEGORY_CODE_9F53,
        &DS_ODS_CARD_9F54,
        &DSDOL_9F5B,
        &DS_REQUESTED_OPERATOR_ID_9F5C,
        &KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D,
        &DS_ID_9F5E,
        &DS_SLOT_AVAILABILITY_9F5F,
        &CVC3_TRACK1_9F60,
        &CVC3_TRACK2_9F61,
        &PCVC3_TRACK1_9F62,
        &PUNATC_TRACK1_9F63,
        &NATC_TRACK1_9F64,
        &PCVC3_TRACK2_9F65,
        &KERNEL2::PUNATC_TRACK2_9F66,
        &NATC_TRACK2_9F67,
        &KERNEL2::UDOL_9F69,
        &UNPREDICTABLE_NUMBER_NUMERIC_9F6A,
        &TRACK2_DATA_9F6B,
        &MS_APPLICATION_VERSION_NUMBER_READER_9F6D,
        &THIRD_PARTY_DATA_9F6E,
        &DS_SLOT_MANAGEMENT_CONTROL_9F6F,
        &PROTECTED_DATA_ENVELOPE1_9F70,
        &PROTECTED_DATA_ENVELOPE2_9F71,
        &PROTECTED_DATA_ENVELOPE3_9F72,
        &PROTECTED_DATA_ENVELOPE4_9F73,
        &PROTECTED_DATA_ENVELOPE5_9F74,
        &UNPROTECTED_DATA_ENVELOPE1_9F75,
        &UNPROTECTED_DATA_ENVELOPE2_9F76,
        &UNPROTECTED_DATA_ENVELOPE3_9F77,
        &UNPROTECTED_DATA_ENVELOPE4_9F78,
        &UNPROTECTED_DATA_ENVELOPE5_9F79,
        &CUSTOMER_EXCLUSIVE_DATA_9F7C,
        &DS_SUMMARY_1_9F7D,
        &MOBILE_SUPPORT_INDICATOR_9F7E,
        &DS_UNPREDICTABLE_NUMBER_9F7F,
        &FCI_PROPRIETARY_TEMPLATE_A5,
        &FCI_ISSUER_DISCRETIONARY_DATA_BF0C,
        &POS_CARDHOLDER_INTERACTION_INFO_DF4B,
        &DS_INPUT_CARD_DF60,
        &DS_DIGEST_H_DF61,
        &DS_ODS_INFO_DF62,
        &DS_ODS_TERM_DF63,
        &BALANCE_READ_BEFORE_GEN_AC_DF8104,
        &BALANCE_READ_AFTER_GEN_AC_DF8105,
        &DATA_NEEDED_DF8106,
        &CDOL1_RELATED_DATA_DF8107,
        &DS_AC_TYPE_DF8108,
        &DS_INPUT_TERM_DF8109,
        &DS_ODS_INFO_FOR_READER_DF810A,
        &DS_SUMMARY_STATUS_DF810B,
        &KERNEL_ID_DF810C,
        &DSVN_TERM_DF810D,
        &POST_GEN_AC_PUT_DATA_STATUS_DF810E,
        &PRE_GEN_AC_PUT_DATA_STATUS_DF810F,
        &PROCEED_TO_FIRST_WRITE_FLAG_DF8110,
        &PDOL_RELATED_DATA_DF8111,
        &TAGS_TO_READ_DF8112,
        &DRDOL_RELATED_DATA_DF8113,
        &REFERENCE_CONTROL_PARAMETER_DF8114,
        &ERROR_INDICATION_DF8115,
        &USER_INTERFACE_REQUEST_DATA_DF8116,
        &CARD_DATA_INPUT_CAPABILITY_DF8117,
        &CVM_CAPABILITY_CVM_REQUIRED_DF8118,
        &CVM_CAPABILITY_NO_CVM_REQUIRED_DF8119,
        &DEFAULT_UDOL_DF811A,
        &KERNEL_CONFIGURATION_DF811B,
        &MAX_LIFETIME_OF_TORN_RECORD_DF811C,
        &MAX_NUMBER_OF_TORN_RECORDS_DF811D,
        &MS_CVM_CAPABILITY_CVM_REQUIRED_DF811E,
        &SECURITY_CAPABILITY_DF811F,
        &TAC_DEFAULT_DF8120,
        &TAC_DENIAL_DF8121,
        &TAC_ONLINE_DF8122,
        &READER_CONTACTLESS_FLOOR_LIMIT_DF8123,
        &READER_CONTACTLESS_TRANSACTION_LIMIT_NO_ON_DEVICE_CVM_DF8124,
        &READER_CONTACTLESS_TRANSACTION_LIMIT_ON_DEVICE_CVM_DF8125,
        &READER_CVM_REQUIRED_LIMIT_DF8126,
        &TIME_OUT_VALUE_DF8127,
        &IDS_STATUS_DF8128,
        &OUTCOME_PARAMETER_SET_DF8129,
        &DD_CARD_TRACK1_DF812A,
        &DD_CARD_TRACK2_DF812B,
        &MS_CVM_CAPABILITY_NO_CVM_REQUIRED_DF812C,
        &MESSAGE_HOLD_TIME_DF812D,
        &HOLD_TIME_VALUE_DF8130,
        &PHONE_MESSAGE_TABLE_DF8131,
        &MIN_RELAY_RESISTENCE_GRACE_PERIOD_DF8132,
        &MAX_RELAY_RESISTENCE_GRACE_PERIOD_DF8133,
        &TERMINAL_EXPECTED_TRANSMISSION_TIME_FOR_C_APDU_DF8134,
        &TERMINAL_EXPECTED_TRANSMISSION_TIME_FOR_R_APDU_DF8135,
        &RELAY_RESISTENCE_ACCURACY_THRESHOLD_DF8136,
        &RELAY_RESISTENCE_TRANSMISSION_TIME_MISMATCH_THRESHOLD_DF8137,
        &TORN_RECORD_FF8101,
        &TAGS_TO_WRITE_BEFORE_GEN_AC_FF8102,
        &TAGS_TO_WRITE_AFTER_GEN_AC_FF8103,
        &DATA_TO_SEND_FF8104,
        &DATA_RECORD_FF8105,
        &DISCRETIONARY_DATA_FF8106,
    };

    static inline const tag_info* all_tags_for_emv_data_record[] = {
        &AMOUNT_AUTHORISED_9F02,
        &AMOUNT_OTHER_9F03,
        &APPLICATION_CRYPTOGRAM_9F26,
        &APPLICATION_EXPIRE_DATE_5F24,
        &AIP_82,
        &APPLICATION_LABEL_50,
        &PAN_5A,
        &PAN_SEQ_5F34,
        &APP_PREFERRED_NAME_9F12,
        &ATC_9F36,
        &AUC_9F07,
        &APPLICATION_VERSION_NUMBER_READER_9F09,
        &CID_9F27,
        &CVM_RESULT_9F34,
        &DF_NAME_84,
        &INTERFACE_DEVICE_SERIAL_NUMBER_9F1E,
        &ISSUER_APPLICATION_DATA_9F10,
        &ISSUER_CODE_TABLE_INDEX_9F11,
        &PAYMENT_ACCOUNT_REFERENCE_9F24,
        &TERMINAL_CAPABILITIES_9F33,
        &TERMINAL_COUNTRY_CODE_9F1A,
        &TERMINAL_TYPE_9F35,
        &TVR_95,
        &TRACK2_57,
        &TRANSACTION_CATEGORY_CODE_9F53,
        &TRANSACTION_CURRENCY_CODE_5F2A,
        &TRANSACTION_DATE_9A,
        &TRANSACTION_TYPE_9C,
        &UNPREDICTABLE_NUMBER_9F37};

    static inline const tag_info* all_tags_for_ms_data_record[] = {
        &APPLICATION_LABEL_50,
        &APP_PREFERRED_NAME_9F12,
        &DF_NAME_84,
        &ISSUER_CODE_TABLE_INDEX_9F11,
        &MS_APPLICATION_VERSION_NUMBER_READER_9F6D,
        &PAYMENT_ACCOUNT_REFERENCE_9F24,
        &TRACK1_DATA_56,
        &TRACK2_57};

    static inline const tag_info* all_tags_for_emv_discretionary_data[] = {
        &KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D,
        &APPLICATION_CURRENCY_CODE_9F42,
        &BALANCE_READ_BEFORE_GEN_AC_DF8104,
        &BALANCE_READ_AFTER_GEN_AC_DF8105,
        &DS_SUMMARY_3_DF8102,
        &DS_SUMMARY_STATUS_DF810B,
        &ERROR_INDICATION_DF8115,
        &PRE_GEN_AC_PUT_DATA_STATUS_DF810F,
        &POST_GEN_AC_PUT_DATA_STATUS_DF810E,
        &THIRD_PARTY_DATA_9F6E,
        &TORN_RECORD_FF8101};

    static inline const tag_info* all_tags_for_ms_discretionary_data[] = {
        &KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D,
        &ERROR_INDICATION_DF8115,
        &THIRD_PARTY_DATA_9F6E,
        &DD_CARD_TRACK1_DF812A,
        &DD_CARD_TRACK2_DF812B};

    static inline const tag_info* all_tags_for_torn_record[] = {
        &AMOUNT_AUTHORISED_9F02,
        &AMOUNT_OTHER_9F03,
        &PAN_5A,
        &PAN_SEQ_5F34,
        &BALANCE_READ_BEFORE_GEN_AC_DF8104,
        &CDOL1_RELATED_DATA_DF8107,
        &CVM_RESULT_9F34,
        &DRDOL_RELATED_DATA_DF8113,
        &DS_SUMMARY_1_9F7D,
        &IDS_STATUS_DF8128,
        &INTERFACE_DEVICE_SERIAL_NUMBER_9F1E,
        &PDOL_RELATED_DATA_DF8111,
        &REFERENCE_CONTROL_PARAMETER_DF8114,
        &TERMINAL_CAPABILITIES_9F33,
        &TERMINAL_COUNTRY_CODE_9F1A,
        &TERMINAL_TYPE_9F35,
        &TVR_95,
        &TRANSACTION_CATEGORY_CODE_9F53,
        &TRANSACTION_CURRENCY_CODE_5F2A,
        &TRANSACTION_DATE_9A,
        &TRANSACTION_TIME_9F21,
        &TRANSACTION_TYPE_9C,
        &UNPREDICTABLE_NUMBER_9F37,
        &DEVIDE_REPLAY_RESISTENCE_ENTROPY_DF8302,
        &TERMINAL_RELAY_RESISTENCE_ENTROPY_DF8301,
        &MIN_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8303,
        &MAX_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8304,
        &DEVICE_ESTIMATED_TRANSMISSION_TIME_DF8305,
        &MEASURED_RELAY_RESISTENCE_PROCESSING_TIME_DF8306,
        &RRP_COUNTER_DF8307};

}; // KERNEL2_NS

namespace KERNEL3 {
DECL_TAG_N(AOSA_9F5D, "Available Offline Spending Amount (AOSA)", 0x9F5D, 12, 12);
DECL_TAG_ANS(CARD_HOLDER_NAME_5F20, "Card Holder Name", 0x5F20, 2, 26, PERM_K | PERM_RA);
DECL_TAG_B(COMMAND_TEMPLATE_83, "Command Template", 0x83, 0, 253);
DECL_TAG_B(SHORT_FILE_IDENTIFIER_88, "Short File Identifier", 0x88, 8, 8, PERM_K | PERM_RA);
DECL_TAG_ANS(AUTHORISATION_CODE_89, "Authorisation Code", 0x89, 6, 6);
DECL_TAG_AN(AUTHORISATION_RESPONSE_CODE_8A, "Authorisation Response Code (ARC)", 0x8A, 2, 2);
DECL_TAG_B(ISSUER_AUTHENTICATION_DATA_91, "Issuer Authentication Data", 0x91, 8, 16);
DECL_TAG_B(AID_9F06, "Application Identifier", 0x9F06, 5, 16);
DECL_TAG_B(ISSUER_SCRIPT_IDENTIFIER_9F18, "Issuer Script Identifier", 0x9F18, 4, 4);
DECL_TAG_B(TERMINAL_FLOOR_LIMIT_9F1B, "Terminal Floor Limit", 0x9F1B, 4, 4);
DECL_TAG_B(APPLICATION_PROGRAM_ID_9F5A, "Application Program ID", 0x9F5A, 1, 6, PERM_K | PERM_RA);
DECL_TAG_B(ISSUER_SCRIPT_RESULTS_9F5B, "Issuer Script Results", 0x9F5B, 0, 253);
DECL_TAG_B(IDS_RECORD_UPDATE_TEMPLATE_BF60, "Integrated Data Storage Record Update Tempate", 0xBF60, 0, 253);
DECL_TAG_B(ISSUER_SCRIPT_TEMPLATE_71, "Issuer Script Template", 0x71, 0, 253);
DECL_TAG_B(ISSUER_SCRIPT_TEMPLATE_72, "Issuer Script Template", 0x72, 0, 253);

static constexpr char CARD_AUTH_RELATED_DATA_9F69_desc[] = "Card Authentication Related Data";
struct TAG_CARD_AUTH_RELATED_DATA_9F69 : public tag_b {
    constexpr TAG_CARD_AUTH_RELATED_DATA_9F69() : tag_b(0x9F69, CARD_AUTH_RELATED_DATA_9F69_desc, 5, 16){};
    static inline uint8_t fdda_version(const std::vector<uint8_t>& v) {
        return v[0];
    };

    static inline std::vector<uint8_t> un(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>{v.begin() + 1, v.begin() + 5};
    };

    static inline std::vector<uint8_t> ctq(const std::vector<uint8_t>& v) {
        return std::vector<uint8_t>{v.begin() + 5, v.begin() + 7};
    };
};
static constexpr TAG_CARD_AUTH_RELATED_DATA_9F69 CARD_AUTH_RELATED_DATA_9F69{};
}; // namespace KERNEL3

struct KERNEL3_NS {
    static inline const tag_sets all_tags_set{
        &ADF_NAME_4F,
        &APPLICATION_LABEL_50,
        &TRACK2_57,
        &PAN_5A,
        &KERNEL3::CARD_HOLDER_NAME_5F20,
        &APPLICATION_EXPIRE_DATE_5F24,
        &ISSUER_COUNTRY_CODE_5F28,
        &TRANSACTION_CURRENCY_CODE_5F2A,
        &LANG_PREF_5F2D,
        &PAN_SEQ_5F34,
        &APPLICATION_TEMPLATE_61,
        &FCI_TEMPLATE_6F,
        &KERNEL3::ISSUER_SCRIPT_TEMPLATE_71,
        &KERNEL3::ISSUER_SCRIPT_TEMPLATE_72,
        &RESPONSE_TEMPLATE_FORMAT_2_77,
        &RESPONSE_TEMPLATE_FORMAT_1_80,
        &AIP_82,
        &KERNEL3::COMMAND_TEMPLATE_83,
        &DF_NAME_84,
        &APPLICATION_PRIORITY_INDICATOR_87,
        &KERNEL3::SHORT_FILE_IDENTIFIER_88,
        &KERNEL3::AUTHORISATION_CODE_89,
        &KERNEL3::AUTHORISATION_RESPONSE_CODE_8A,
        &CA_PUBLIC_KEY_INDEX_8F,
        &ISSUER_PUB_KEY_CERT_90,
        &KERNEL3::ISSUER_AUTHENTICATION_DATA_91,
        &ISSUER_PUB_KEY_REMAINER_92,
        &AFL_94,
        &TVR_95,
        &TRANSACTION_DATE_9A,
        &TRANSACTION_TYPE_9C,
        &AMOUNT_AUTHORISED_9F02,
        &AMOUNT_OTHER_9F03,
        &KERNEL3::AID_9F06,
        &AUC_9F07,
        &ISSUER_APPLICATION_DATA_9F10,
        &ISSUER_CODE_TABLE_INDEX_9F11,
        &APP_PREFERRED_NAME_9F12,
        &KERNEL3::ISSUER_SCRIPT_IDENTIFIER_9F18,
        &TERMINAL_COUNTRY_CODE_9F1A,
        &KERNEL3::TERMINAL_FLOOR_LIMIT_9F1B,
        // 9F22
        &PAYMENT_ACCOUNT_REFERENCE_9F24,
        &APPLICATION_CRYPTOGRAM_9F26,
        &CID_9F27,
        &ISSUER_PUB_KEY_EXP_9F32,
        &ATC_9F36,
        &UNPREDICTABLE_NUMBER_9F37,
        &PDOL_9F38,
        &ICC_PUB_KEY_CERT_9F46,
        &ICC_PUB_KEY_EXP_9F47,
        &ICC_PUB_KEY_REMAINER_9F48,
        &SDA_TAG_LIST_9F4A,
        &SDAD_9F4B,
        &LOG_ENTRY_9F4D,
        &MERCHANT_NAME_AND_LOCATION_9F4E,
        &KERNEL3::APPLICATION_PROGRAM_ID_9F5A,
        &KERNEL3::ISSUER_SCRIPT_RESULTS_9F5B,
        &KERNEL3::AOSA_9F5D,
        &TTQ_9F66,
        &KERNEL3::CARD_AUTH_RELATED_DATA_9F69,
        &CTQ_9F6C,
        &FFI_9F6E,
        &CUSTOMER_EXCLUSIVE_DATA_9F7C,
        &FCI_PROPRIETARY_TEMPLATE_A5,
        &FCI_ISSUER_DISCRETIONARY_DATA_BF0C,
        &KERNEL3::IDS_RECORD_UPDATE_TEMPLATE_BF60,
        &IDSD_D2};
};

// tags used mostly for entry point and kernel agnostic
static const tag_sets all_tags_set{
    &ASRPD_9F0A,
    &EXTENDED_SELECTION_9F29,
    &KERNEL_IDENTIFIER_9F2A,
    &TTQ_9F66,
    &TRANSACTION_TYPE_9C,
    &AMOUNT_AUTHORISED_9F02,
    &AMOUNT_OTHER_9F03,
    &UNPREDICTABLE_NUMBER_9F37,
    &UNPREDICTABLE_NUMBER_NUMERIC_9F6A,
    &TRANSACTION_CURRENCY_CODE_5F2A,
    &ADF_NAME_4F,
    &APPLICATION_LABEL_50,
    &APPLICATION_PRIORITY_INDICATOR_87,
    &KERNEL_IDENTIFIER_9F2A,
    &APPLICATION_TEMPLATE_61,
    &DF_NAME_84,
    &PDOL_9F38,
    &LANG_PREF_5F2D,
    &APP_PREFERRED_NAME_9F12,
    &IDSD_D2,
    &DIRECTORY_ENTRY_61,
    &FCI_ISSUER_DISCRETIONARY_DATA_BF0C,
    &FCI_PROPRIETARY_TEMPLATE_A5,
    &FCI_TEMPLATE_6F,
    &MERCHANT_NAME_AND_LOCATION_9F4E,
    &TRANSACTION_DATE_9A,
    &TRANSACTION_TIME_9F21,
    &TERMINAL_COUNTRY_CODE_9F1A,
    &TERMINAL_CAPABILITIES_9F33,
    &ACQUIRER_IDENTIFIER_9F01,
    &DS_ID_9F5E,
    &KERNEL_ID_DF810C,
    &MERCHANT_CATEGORY_CODE_9F15,
    &MERCHANT_IDENTIFIER_9F16,
    &TERMINAL_TYPE_9F35,
    &TERMINAL_IDENTIFICATION_9F1C,
    &TRANSACTION_CATEGORY_CODE_9F53,
    &TRANSACTION_CURRENCY_EXPONENT_5F36};

const tag_sets* active_kernel_tag_set = nullptr;

const tag_info* find_tag_info(uint32_t tag) {
    tag_info t{tag, TAG_TYPE::B, nullptr, 0, 0};

    if (active_kernel_tag_set != nullptr) {
        auto q = active_kernel_tag_set->find(&t);
        if (q != active_kernel_tag_set->end()) {
            return *q;
        }
    };

    auto p = all_tags_set.find(&t);
    if (p != all_tags_set.end()) {
        return *p;
    }

    return nullptr;
}

bool tag_has_permission(uint32_t tag, TAG_PERM perm) {
    auto info = find_tag_info(tag);
    if (info != nullptr) {
        return info->has_permission(perm);
    }
    return false;
};

bool tag_is_known(uint32_t tag) {
    return find_tag_info(tag) != nullptr;
};

bool tlv_validate(uint32_t tag, std::vector<uint8_t> const& value) {
    auto p = find_tag_info(tag);
    if (p != nullptr) {
        return p->validate(value);
    }
    // for not supported tags, we consider it all good
    return true;
}

#ifdef HAVE_LOG
void tlv_print(uint32_t tag, std::vector<uint8_t> const& value,
               const std::string prefix = std::string{}) {
    pr_debug(prefix, "<", to_hex(tag), "> : ");
    auto info = find_tag_info(tag);
    if (info != nullptr) {
        pr_debug(std::string(info->desc), " [", info->to_string(value), "]\n");
    } else {
        pr_debug("Unknown [", value, "]\n");
    };
};
#else
#define tlv_print(...)
#endif

bool tag_list_deserialize(std::vector<uint8_t>::const_iterator begin,
                          std::vector<uint8_t>::const_iterator end,
                          std::set<uint32_t>& tags) {
    uint32_t tag = 0;
    uint8_t tagSize = 0;
    while (begin < end) {
        if (*begin == 0x00) {
            begin++;
            continue;
        }

        if (!tlv_get_tag(begin, end, tag, tagSize)) {
            return false;
        }

        tags.insert(tag);
    }

    return true;
};

inline bool tag_list_deserialize(std::vector<uint8_t> const& list, std::set<uint32_t>& tags) {
    return tag_list_deserialize(list.begin(), list.end(), tags);
};

struct dol_elem {
    uint32_t tag;
    uint32_t length;
};

template <typename Iter>
bool tlv_parse_dol(Iter begin, Iter end, std::vector<dol_elem>& dol) {
    uint32_t tag = 0;
    uint8_t tagSize = 0;
    uint32_t length;
    std::vector<dol_elem> tmp{};

    while (begin < end) {
        if (*begin == 0x00) {
            begin++;
            continue;
        }

        if (!tlv_get_tag(begin, end, tag, tagSize) || !tlv_get_length(begin, end, length)) {
            return false;
        }

        tmp.push_back(dol_elem{tag, length});
    }

    tmp.swap(dol);
    return true;
};

struct COMMAND {
    constexpr COMMAND(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) : cla{cla}, ins{ins}, p1{p1}, p2{p2} {};
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
};

struct COMMANDS {
    static constexpr COMMAND SELECT = COMMAND{0x00, 0xA4, 0x04, 0x00};
    static constexpr COMMAND READ_RECORD = COMMAND{0x00, 0xB2, 0x00, 0x00};
    static constexpr COMMAND GPO = COMMAND{0x80, 0xA8, 0x00, 0x00};
    static constexpr COMMAND GET_DATA = COMMAND{0x80, 0xCA, 0x00, 0x00};
    static constexpr COMMAND GET_RESPONSE = COMMAND{0x00, 0x0C, 0x00, 0x00};
    static constexpr COMMAND EXCHANGE_RELAY_RESISTANCE_DATA = COMMAND{0x80, 0xEA, 0x00, 0x00};
    static constexpr COMMAND PUT_DATA = COMMAND{0x80, 0xDA, 0x00, 0x00};
    static constexpr COMMAND COMPUTE_CRYPTOGRAPHIC_CHECKSUM = COMMAND{0x80, 0x2A, 0x8E, 0x80};
    static constexpr COMMAND GENERATE_AC = COMMAND{0x80, 0xAE, 0x00, 0x00};
    static constexpr COMMAND RECOVER_AC = COMMAND{0x00, 0xD0, 0x00, 0x00};
};

class apdu_builder {
public:
    struct build_state {
        std::vector<uint8_t> to_bytes() {
            std::vector<uint8_t> apdu{};
            apdu.push_back(_cla);
            apdu.push_back(_ins);
            apdu.push_back(_p1);
            apdu.push_back(_p2);
            if (_data.size() != 0) {
                uint8_t lc = _data.size();
                apdu.push_back(lc);
                for (auto p = _data.begin(); p != _data.end(); p++)
                    apdu.push_back(*p);
            }
            if (have_le) {
                apdu.push_back(_le);
            }

            return apdu;
        };

        build_state& p1(uint8_t val) {
            _p1 = val;
            return *this;
        };

        build_state& p2(uint8_t val) {
            _p2 = val;
            return *this;
        }

        build_state& le(uint8_t val) {
            _le = val;
            have_le = true;
            return *this;
        }

        build_state& data(const std::vector<uint8_t>& val) {
            _data = val;
            return *this;
        }

        build_state& data(std::vector<uint8_t>&& val) {
            _data = val;
            return *this;
        }

        uint8_t _cla;
        uint8_t _ins;
        uint8_t _p1;
        uint8_t _p2;
        uint8_t _le;
        bool have_le;
        std::vector<uint8_t> _data;
    };

    static build_state build(const COMMAND& cmd) {
        build_state state;
        state._cla = cmd.cla;
        state._ins = cmd.ins;
        state._p1 = cmd.p1;
        state._p2 = cmd.p2;
        state._le = 0;
        state.have_le = false;
        state._data = std::vector<uint8_t>{};
        return state;
    };
};

class message;
class message_router {
public:
    virtual void post(const message& msg) = 0;
    virtual void start() = 0;
};

extern message_router* emv_message_router;

class timer {
public:
    timer(long msecs, std::function<void()> timer_callback) : timer_callback{timer_callback}, msecs{msecs} {};
    virtual void start() = 0;
    virtual void stop() = 0;
    void set_duration(long duration) { msecs = duration; };
    virtual ~timer(){};

protected:
    std::function<void()> timer_callback;
    long msecs;
};

class timer_factory {
public:
    virtual std::unique_ptr<timer> create(long msecs, std::function<void()> timer_callback) = 0;
};

extern timer_factory* emv_timer_factory;

class message {
public:
    static constexpr int MAX_MESSAGE_LENGTH = 512;
    message(const std::vector<uint8_t> msg) : data(msg){};
    message(std::vector<uint8_t>&& msg) : data(msg){};
    message(MESSAGE_ID id, EMV_MODULE src, EMV_MODULE dest, const std::vector<uint8_t> body = std::vector<uint8_t>()) {
        data.resize(3 + body.size());
        data[0] = static_cast<uint8_t>(id);
        data[1] = static_cast<uint8_t>(src);
        data[2] = static_cast<uint8_t>(dest);
        std::copy(body.begin(), body.end(), data.begin() + 3);
    };
    EMV_MODULE get_source() const { return static_cast<EMV_MODULE>(data[1]); };
    EMV_MODULE get_destination() const { return static_cast<EMV_MODULE>(data[2]); };
    MESSAGE_ID get_message_id() const { return static_cast<MESSAGE_ID>(data[0]); };
    std::vector<uint8_t> get_body() const { return std::vector<uint8_t>(data.begin() + 3, data.end()); };
    std::vector<uint8_t>::const_iterator body_begin() const { return data.cbegin() + 3; };
    std::vector<uint8_t>::const_iterator body_end() const { return data.cend(); };
    const std::vector<uint8_t>& get_raw_data() const { return data; };
    void send() {
        emv_message_router->post(*this);
    }

private:
    std::vector<uint8_t> data;
};

void send_ui_event(const struct ui_req_data& ui) {
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>(ui.ui_id));
    data.push_back(static_cast<uint8_t>(ui.status));
    // TODO to send value stuff
    message out{MESSAGE_ID::TERMINAL_UI_REQ, EMV_MODULE::L2, EMV_MODULE::TERMINAL, data};
    out.send();
};

class emv_module {
public:
    emv_module(){};
    virtual ~emv_module(){};
    virtual void handle_message(const message& msg) = 0;
    virtual bool are_you(EMV_MODULE who) const = 0;
};

class mqueue {
public:
    // locker primitive whose implementation is os dependent
    // it provoides mutex and condition variable like behavior
    struct qlocker {
        virtual void lock() = 0;
        virtual void unlock() = 0;
        virtual void wait(std::function<bool()>) = 0;
        virtual void notify() = 0;
    };

    struct mq_lock_guard {
        mq_lock_guard(struct qlocker* lk) : lk(lk) { lk->lock(); };
        ~mq_lock_guard() { lk->unlock(); };
        qlocker* lk;
    };

    mqueue(qlocker* locker) : locker(locker){};

    void add_consumer(emv_module* consumer) {
        consumers.push_back(consumer);
    };

    bool have_consumer(const message& msg) const {
        for (auto consumer : consumers) {
            if (consumer->are_you(msg.get_destination())) {
                return true;
            }
        }
        return false;
    };

    bool empty() const {
        return queue.empty();
    };

    void post(const message& msg) {
        mq_lock_guard guard(locker);
        queue.push_back(msg);
        locker->notify();
    }

    void post(message&& msg) {
        mq_lock_guard guard(locker);
        queue.push_back(std::move(msg));
        locker->notify();
    }

    void loop() {
        while (true) {
            locker->wait([&] { return !queue.empty(); });
            while (!queue.empty()) {
                for (auto consumer : consumers) {
                    auto& msg = queue.front();
                    if (!consumer->are_you(msg.get_destination()))
                        continue;
                    consumer->handle_message(msg);
                    mq_lock_guard guard(locker);
                    queue.pop_front();
                    break;
                }
            }
        }
    }

private:
    std::list<message> queue;
    struct qlocker* locker;
    std::vector<emv_module*> consumers;
};

using tlv_obj = std::pair<uint32_t, std::vector<uint8_t>>;

class tlv_obj_list {
public:
    tlv_obj_list(std::vector<uint8_t> const& v) : _list(v){};
    tlv_obj_list() : _list(std::vector<uint8_t>{}){};

    inline void append(std::vector<uint8_t> const& data) {
        std::copy(data.begin(), data.end(), back_inserter(_list));
    };

    template <typename Iter>
    void append(Iter begin, Iter end) {
        std::copy(begin, end, back_inserter(_list));
    };

    inline void initialize() {
        _list.clear();
    };

    inline bool empty() {
        return _list.size() == 0;
    }

    tlv_obj get_and_remove_from_list() {
        uint32_t tag = 0;
        uint8_t tagSize = 0;
        uint32_t length;
        auto begin = _list.cbegin();
        auto end = _list.cend();

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
            _list = std::vector<uint8_t>{begin + length, end};
            return obj;
        }

        return tlv_obj{};
    };

private:
    std::vector<uint8_t> _list;
};

using tlv_maps = std::map<uint32_t, std::vector<uint8_t>>;

class tlv_db {
public:
    tlv_db() : maps{} {};
    tlv_db(const tlv_db& db) : maps{db.maps} {};
    tlv_db(tlv_db&& db) : maps{std::move(db.maps)} {};
    tlv_db& operator=(const tlv_db& db) {
        maps = db.maps;
        return *this;
    };

    bool parse(const std::vector<uint8_t>& tlv_list) {
        auto p = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable {
            if (constructed)
                return true;
            std::vector<uint8_t> value(begin, end);
            tlv_print(tag, value);
            if (!tlv_validate(tag, value)) {
                logger.error("tag validate failed\n");
                return false;
            }
            tlv_obj obj(tag, std::move(value));
            insert(std::move(obj));
            return true;
        };
        return tlv_visit(tlv_list.begin(), tlv_list.end(), p);
    };

    tlv_db& insert(const tlv_db& db) {
        maps.insert(db.maps.begin(), db.maps.end());
        return *this;
    };

    tlv_db& insert(const tlv_obj& obj) {
        maps.insert(obj);
        return *this;
    }

    tlv_db& insert(tlv_obj&& obj) {
        maps.insert(std::move(obj));
        return *this;
    };

    template <typename... Args>
    tlv_db& emplace(Args&&... args) {
        tlv_obj obj(std::forward<Args>(args)...);
        insert(std::move(obj));
        return *this;
    };

    tlv_db& update(const tlv_obj& obj) {
        auto p = maps.find(obj.first);
        if (p != maps.end()) {
            p->second = obj.second;
            return *this;
        }
        return insert(obj);
    }

    tlv_db& update(const tlv_db& db) {
        for (auto& p : db.maps) {
            update(p);
        }
        return *this;
    }

    bool has_tag(uint32_t tag) const {
        auto p = maps.find(tag);
        return p != maps.end();
    };

    bool has_tag(const tag_info& tag) const { return has_tag(tag.id); };

    bool has_empty_tag(int tag) const {
        auto p = maps.find(tag);
        if (p != maps.end()) {
            return p->second.size() == 0;
        }
        return false;
    }

    inline bool has_empty_tag(const tag_info& tag) const {
        return has_empty_tag(tag.id);
    }

    bool has_non_empty_tag(uint32_t tag) const {
        return has_tag(tag) && get(tag).size() != 0;
    }

    inline bool has_non_empty_tag(const tag_info& tag) const {
        return has_non_empty_tag(tag.id);
    }

    inline tlv_obj get_and_remove_from_list(const tag_info& tag) {
        return get_and_remove_from_list(tag.id);
    };

    tlv_obj get_and_remove_from_list(uint32_t tag_list) {
        auto& list_data = (*this)[tag_list];
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

            if (!tlv_get_tag(begin, end, tag, tagSize) || !tlv_get_length(begin, end, length) ||
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

    std::vector<uint8_t> const& operator[](const tag_info& tag) const { return get(tag); };
    std::vector<uint8_t> const& operator[](uint32_t tag) const { return get(tag); };
    std::vector<uint8_t>& operator[](const tag_info& tag) { return get(tag); };
    std::vector<uint8_t>& operator[](uint32_t tag) { return get(tag); };

    void set_bit(tag_info const& tag, const tag_bit_field& pos) {
        v_set_bit(get(tag), pos);
    };

    void clear_bit(tag_info const& tag, const tag_bit_field& pos) {
        v_clear_bit(get(tag), pos);
    };

    int get_bit(tag_info const& tag, const tag_bit_field& pos) const {
        return v_get_bit(get(tag), pos);
    };

    // TODO CHECK it's N type
    numeric_value_type get_numeric_value(tag_info const& tag) const {
        return tag_n::to_numeric_value(get(tag));
    };

    std::vector<uint8_t> to_tlv(uint32_t tag) const {
        return make_tlv(tag, get(tag));
    };

    inline std::vector<uint8_t> to_tlv(tag_info const& tag) const {
        return to_tlv(tag.id);
    };

    void initialize(const tag_info& tag) {
        tlv_obj obj{tag.id, std::vector<uint8_t>(tag.minlen)};
        update(obj);
    };

    tlv_db& operator+=(const tlv_db& db) {
        insert(db);
        return *this;
    }

    size_t size() const {
        return maps.size();
    }

    void clear() {
        maps.clear();
    };

    void print(const tag_info& info, const std::string prefix = std::string{}) const {
        tlv_print(info.id, get(info), prefix);
    };

    void print(const std::string prefix = std::string{}) const {
        for (auto& p : maps) {
            tlv_print(p.first, p.second, prefix);
        }
    };

    // if TAG define a custom_value method, return it for operator()
    template <typename TAG>
    auto operator()(TAG& tag) const -> decltype(tag.custom_value(std::vector<uint8_t>{})) {
        return tag.custom_value(get(tag));
    };

    // otherwise return to_string
    template <typename TAG, typename... Args>
    std::string operator()(TAG tag, Args&&... args) const {
        return tag.to_string(get(tag));
    };

    tlv_maps::const_iterator begin() const {
        return maps.cbegin();
    };

    tlv_maps::const_iterator end() const {
        return maps.cend();
    };

    void remove(uint32_t tag) {
        auto p = maps.find(tag);
        if (p != maps.end()) {
            maps.erase(p);
        }
    };

    void swap(tlv_db& db) {
        maps.swap(db.maps);
    };

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> output{};
        for (auto& tlv : maps) {
            auto data = make_tlv(tlv.first, tlv.second);
            std::copy(data.begin(), data.end(), back_inserter(output));
        };
        return output;
    };

private:
    std::vector<uint8_t>& get(uint32_t tag) {
        auto p = maps.find(tag);
        if (p == maps.end()) {
            pr_debug("get a mutable tag ", to_hex(tag), " that does not exist\n");
            throw std::bad_exception();
        };

        return p->second;
    };

    inline std::vector<uint8_t>& get(const tag_info& tag) {
        return get(tag.id);
    };

    std::vector<uint8_t> const& get(uint32_t tag) const {
        auto p = maps.find(tag);
        if (p == maps.end()) {
            pr_debug("get a  tag ", to_hex(tag), " that does not exist\n");
            throw std::bad_exception();
        }

        return p->second;
    };

    std::vector<uint8_t> const& get(const tag_info& tag) const { return get(tag.id); };

    tlv_maps maps;
};

class torn_transaction : public tlv_db {
public:
    torn_transaction() : tlv_db(){};

    template <typename Iter>
    torn_transaction(Iter begin, Iter end) : tlv_db() {
        auto p = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable {
            if (constructed)
                return true;
            std::vector<uint8_t> value(begin, end);
            tlv_obj obj(tag, std::move(value));
            insert(std::move(obj));
            return true;
        };
        tlv_visit(begin, end, p);
    };
};

class torn_records {
public:
    torn_records(){};

    torn_records(const std::vector<uint8_t>& history){};
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> archive{};
        for (auto p = transactions.begin(); p != transactions.end(); ++p) {
            auto record = (*p).serialize();
            auto tlv = make_tlv(TORN_RECORD_FF8101.id, record);
            std::copy(tlv.begin(), tlv.end(), back_inserter(archive));
        }

        return archive;
    };

    void deserialize(const std::vector<uint8_t>& archive) {
        auto p = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable {
            if (constructed && tag == TORN_RECORD_FF8101.id) {
                torn_transaction t{begin, end};
                transactions.push_back(t);
            }
            return true;
        };

        tlv_visit(archive.begin(), archive.end(), p);
    };

    std::list<torn_transaction>::const_iterator cbegin() {
        return transactions.cbegin();
    }

    std::list<torn_transaction>::const_iterator cend() {
        return transactions.cend();
    }

    std::list<torn_transaction>::const_iterator find(const tlv_db& db) {
        for (auto p = transactions.cbegin(); p != transactions.cend(); ++p) {
            if (db.has_non_empty_tag(PAN_SEQ_5F34)) {
                if ((*p)[PAN_5A] == db[PAN_5A] &&
                    p->has_tag(PAN_SEQ_5F34) &&
                    (*p)[PAN_SEQ_5F34] == db[PAN_SEQ_5F34]) {
                    return p;
                };
            } else {
                if ((*p)[PAN_5A] == db[PAN_5A] &&
                    !p->has_tag(PAN_SEQ_5F34)) {
                    return p;
                };
            };
        };

        return transactions.cend();
    }

    void remove(std::list<torn_transaction>::const_iterator pos) {
        transactions.erase(pos);
    };

    template <typename NS>
    void create(tlv_db& db) {
        torn_transaction record{};
        for (auto p : NS::all_tags_for_torn_record) {
            if (db.has_non_empty_tag(p->id)) {
                tlv_obj obj{p->id, db[p->id]};
                record.insert(std::move(obj));
            };
        };

        auto max = db[MAX_NUMBER_OF_TORN_RECORDS_DF811D][0];
        if (transactions.size() >= max) {
            auto& back = transactions.back();
            db.initialize(TORN_RECORD_FF8101);
            auto& torn = db[TORN_RECORD_FF8101];
            torn = back.serialize();
            transactions.pop_back();
        };

        transactions.push_front(record);
    };

private:
    std::list<torn_transaction> transactions;
};

static bool build_dol(uint32_t dol_tag, const std::vector<uint8_t>& dol, const tlv_db& db, std::vector<uint8_t>& tags, std::vector<uint8_t>& missing_tags) {
    pr_debug("build DOL : ", std::string(find_tag_info(dol_tag)->desc), " ", dol, "\n");
    bool success = true;
    std::vector<dol_elem> elems;
    tlv_parse_dol(dol.begin(), dol.end(), elems);

    std::vector<uint8_t> ret;
    for (auto p = elems.begin(); p != elems.end(); ++p) {
        auto& e = *p;
        tag_info t{e.tag, TAG_TYPE::B, nullptr, 0, 0};
        auto info = find_tag_info(e.tag);
        if (!db.has_tag(e.tag) || info == nullptr) {
            auto v = std::vector<uint8_t>(e.length);
            pr_debug(to_hex(e.tag), " ", info == nullptr ? std::string("Unknon") : std::string(info->desc), " default DOL ", v, "\n");
            std::copy(v.begin(), v.end(), back_inserter(ret));
        } else {
            if (db.has_empty_tag(e.tag)) {
                success = false;
                auto p = tag_in_bytes(e.tag);
                pr_debug(to_hex(e.tag), " ", std::string(info->desc), " *** missing ***", "\n");
                std::copy(p.begin(), p.end(), std::back_inserter(missing_tags));
            }
            uint32_t len = e.length;
            auto& actual = db[e.tag];
            // last element of DSDOL no padding if length less than requested
            if (dol_tag == DSDOL_9F5B.id && actual.size() < len && p + 1 == elems.end()) {
                len = actual.size();
            };
            auto v = info->DOL(actual, len);
            pr_debug(to_hex(e.tag), " ", std::string(info->desc), " [", db[e.tag], "]", " DOL ", v, "\n");
            std::copy(v.begin(), v.end(), back_inserter(ret));
        }
    }

    pr_debug("final : ", ret, "\n");
    tags.swap(ret);
    return success;
};

namespace contactless {

enum class KERNEL_ID : uint8_t {
    KERNEL_2 = 2,
    KERNEL_3 = 3,
    KERNEL_4 = 4,
    KERNEL_5 = 5,
    KERNEL_6 = 6,
    KERNEL_7 = 7
};

Logger& operator<<(Logger& l, const ui_req_data& ui) {
    l << "\n\n";
    l << "----------------------------------------------------------------------\n";
    l << "| Message Identifier : " << byte2hex(static_cast<uint8_t>(ui.ui_id)) << " " << to_string(ui.ui_id) << "\n";
    l << "| Status : " << to_string(ui.status) << "\n";
    l << "| Hold time : " << std::to_string(static_cast<int>(ui.hold_time)) << "\n";

    switch (ui.value_type) {
    case ui_value_id::AMOUNT:
        l << "| Amount : <currency code " << ui.currency_code << "> " << ui.value << "\n";
        break;
    case ui_value_id::BALANCE:
        l << "| Blance : <currency code " << ui.currency_code << "> " << ui.value << "\n";
        break;
    default:
        break;
    }
    l << "------------------------------------------------------------------------\n";

    return l;
};

Logger& operator<<(Logger& l, const outcome& oc) {
    l << "OUTCOME : ";
    switch (oc.type) {
    case OUTCOME_TYPE::SELECT_NEXT:
        l << "Select Next\n";
        break;
    case OUTCOME_TYPE::TRY_AGAIN:
        l << "Try Again\n";
        break;
    case OUTCOME_TYPE::APPROVED:
        l << "Approved\n";
        break;
    case OUTCOME_TYPE::DECLINED:
        l << "Declined\n";
        break;
    case OUTCOME_TYPE::ONLINE_REQUEST:
        l << "Online Request\n";
        break;
    case OUTCOME_TYPE::TRY_ANOTHER_INTERFACE:
        l << "Try Another Interface\n";
        break;
    case OUTCOME_TYPE::END_APPLICATION:
        l << "End Application\n";
        break;
    default:
        break;
    };

    l << "Restart : ";
    switch (oc.start) {
    case RESTART_POINT::A:
        l << "A\n";
        break;
    case RESTART_POINT::B:
        l << "B\n";
        break;
    case RESTART_POINT::C:
        l << "C\n";
        break;
    case RESTART_POINT::D:
        l << "D\n";
        break;
    case RESTART_POINT::NA:
        l << "N/A\n";
        break;
    default:
        break;
    }

    l << "Online Response Data : ";
    switch (oc.kernel_restart_cond) {
    case OUTCOME_KERNEL_RESTART_COND::EMV_DATA_AVAIL:
        l << "EMV Data\n";
        break;
    case OUTCOME_KERNEL_RESTART_COND::ANY:
        l << "Any\n";
        break;
    case OUTCOME_KERNEL_RESTART_COND::NA:
        l << "NA\n";
        break;
    }

    l << "CVM : ";
    switch (oc.cvm) {
    case OUTCOME_CVM::ONLINE_PIN:
        l << "Online PIN\n";
        break;
    case OUTCOME_CVM::CONF_CODE_VERIFIED:
        l << "Confirm Code Verified\n";
        break;
    case OUTCOME_CVM::SIGNATURE:
        l << "Signature\n";
        break;
    case OUTCOME_CVM::NO_CVM:
        l << "NO CVM\n";
        break;
    case OUTCOME_CVM::NA:
        l << "N/A\n";
        break;
    }

    l << "UI on Outcome Present : ";
    if (oc.ui_request) {
        l << "Yes\n";
        //l << oc.ui_request_data;
    } else {
        l << "No\n";
    }

    l << "UI on Restart Present : ";
    if (oc.ui_on_restart) {
        l << "Yes\n";
        //l << oc.ui_restart_data;
    } else {
        l << "No\n";
    }

    l << "Data Record Present : ";
    if (oc.data_record_present) {
        l << "\n"
          << oc.data_record << "\n";
    } else {
        l << "No\n";
    }

    l << "Discretionary Data Present : ";
    if (oc.discretionary_data_present) {
        l << "\n"
          << oc.discretionary_data << "\n";
    } else {
        l << "No\n";
    }

    l << "Alternate Interface Preference : ";
    switch (oc.alt_interface) {
    case INTERFACE_TYPE::CONTACT:
        l << "Contact\n";
        break;
    case INTERFACE_TYPE::MAGSTRIPE:
        l << "Magstipe\n";
        break;
    case INTERFACE_TYPE::NA:
        l << "N/A\n";
        break;
    default:
        break;
    }

    l << "Receipt : ";
    if (oc.receipt) {
        l << "Yes\n";
    } else {
        l << "No\n";
    }

    l << "Field Off Request : ";
    if (oc.field_off_request < 0) {
        l << "N/A\n";
    } else {
        l << oc.field_off_request << "\n";
    }

    l << "Removal Timeout : " << oc.removal_timeout << "\n";
    return l;
};

class outcome_builder {
private:
    template <unsigned N>
    void add_data_sets_if_present(const tag_info* (&data_sets)[N], const tag_info& tag) {
        auto& data = db[tag];
        for (auto p : data_sets) {
            if (db.has_tag(p->id)) {
                auto tlv = db.to_tlv(p->id);
                std::copy(tlv.begin(), tlv.end(), back_inserter(data));
            }
        }
    };

public:
    outcome_builder(tlv_db& db) : db{db}, outcome_data{db[OUTCOME_PARAMETER_SET_DF8129]},
                                  uintf{db[USER_INTERFACE_REQUEST_DATA_DF8116]}, output{tlv_db{}} {};

    template <typename NS>
    outcome_builder& create_emv_dr() {
        v_set_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::data_record_present);
        db.initialize(DATA_RECORD_FF8105);
        add_data_sets_if_present(NS::all_tags_for_emv_data_record, DATA_RECORD_FF8105);
        return *this;
    }

    template <typename NS>
    outcome_builder& create_ms_dr() {
        v_set_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::data_record_present);
        db.initialize(DATA_RECORD_FF8105);
        add_data_sets_if_present(NS::all_tags_for_ms_data_record, DATA_RECORD_FF8105);
        return *this;
    }

    template <typename NS>
    outcome_builder& create_emv_dd() {
        v_set_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::discretionary_data_present);
        db.initialize(DISCRETIONARY_DATA_FF8106);
        add_data_sets_if_present(NS::all_tags_for_emv_discretionary_data, DISCRETIONARY_DATA_FF8106);

        return *this;
    }

    template <typename NS>
    outcome_builder& create_ms_dd() {
        v_set_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::discretionary_data_present);
        db.initialize(DISCRETIONARY_DATA_FF8106);
        add_data_sets_if_present(NS::all_tags_for_ms_discretionary_data, DISCRETIONARY_DATA_FF8106);

        return *this;
    }

    outcome_builder& ui(ui_message_id msg, ui_status_id status) {
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_message_id(uintf, msg);
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_status(uintf, status);
        return *this;
    };

    outcome_builder& ui(ui_message_id msg) {
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_message_id(uintf, msg);
        return *this;
    };

    outcome_builder& ui(ui_status_id status) {
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_status(uintf, status);
        return *this;
    };

    outcome_builder& ui(ui_value_id qualifier, const std::vector<uint8_t>& value) {
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_value_qualifier(uintf, qualifier);
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_value(uintf, value);
        return *this;
    };

    outcome_builder& currency(const std::vector<uint8_t>& code) {
        auto& v = db[USER_INTERFACE_REQUEST_DATA_DF8116];
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_currency_code(v, code);
        return *this;
    };

    outcome_builder& field_off(uint8_t time = 0xFF) {
        TAG_OUTCOME_PARAMETER_SET_DF8129::set_field_off(outcome_data, time);
        return *this;
    };

    outcome_builder& hold(std::vector<uint8_t> time = std::vector<uint8_t>(3)) {
        auto& v = db[USER_INTERFACE_REQUEST_DATA_DF8116];
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::set_hold_time(v, time);
        return *this;
    };

    outcome_builder& msg_on_error(ui_message_id error) {
        auto& error_ind = db[ERROR_INDICATION_DF8115];
        TAG_ERROR_INDICATION_DF8115::set_msg_on_error(error_ind, error);
        return *this;
    };

    outcome_builder& ui_on_restart() {
        v_set_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::ui_request_on_restart_present);
        return *this;
    };

    outcome_builder& ui_on_outcome() {
        v_set_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::ui_request_on_outcome_present);
        return *this;
    };

    outcome_builder& status(OUTCOME_TYPE type) {
        TAG_OUTCOME_PARAMETER_SET_DF8129::set_status(outcome_data, type);
        return *this;
    }

    outcome_builder& cvm(OUTCOME_CVM type) {
        TAG_OUTCOME_PARAMETER_SET_DF8129::set_cvm(outcome_data, type);
        return *this;
    }

    outcome_builder& receipt(bool required) {
        if (required) {
            v_set_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::receipt_required);
        } else {
            v_clear_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::receipt_required);
        }
        return *this;
    }

    outcome_builder& error(L3_ERROR error) {
        auto& error_ind = db[ERROR_INDICATION_DF8115];
        TAG_ERROR_INDICATION_DF8115::set_l3_error(error_ind, error);
        return *this;
    }

    outcome_builder& error(L2_ERROR error) {
        auto& error_ind = db[ERROR_INDICATION_DF8115];
        TAG_ERROR_INDICATION_DF8115::set_l2_error(error_ind, error);
        return *this;
    }

    outcome_builder& error(uint8_t sw1, uint8_t sw2) {
        auto& error_ind = db[ERROR_INDICATION_DF8115];
        TAG_ERROR_INDICATION_DF8115::set_l2_error(error_ind, L2_ERROR::STATUS_BYTES);
        TAG_ERROR_INDICATION_DF8115::set_sw12(error_ind, sw1, sw2);
        return *this;
    }

    outcome_builder& start(RESTART_POINT start) {
        TAG_OUTCOME_PARAMETER_SET_DF8129::set_start(outcome_data, RESTART_POINT::B);
        return *this;
    };

    outcome_builder& error(L1_ERROR error) {
        auto& error_ind = db[ERROR_INDICATION_DF8115];
        TAG_ERROR_INDICATION_DF8115::set_l1_error(error_ind, error);
        return *this;
    }

    outcome_builder& initialize(const tag_info& tag) {
        db.initialize(tag);
        return *this;
    };

    outcome_builder& pack(const tag_info& tag) {
        output.emplace(tag.id, db[tag]);
        return *this;
    };

    outcome_builder& add_to_list(const tag_info& tag, const tag_info& list) {
        auto& v = db[list];
        auto tlv = db.to_tlv(tag);
        std::copy(tlv.begin(), tlv.end(), back_inserter(v));
        return *this;
    };

    // post outcome
    outcome post() {
        outcome o{TAG_OUTCOME_PARAMETER_SET_DF8129::get_status(outcome_data)};
        o.start = TAG_OUTCOME_PARAMETER_SET_DF8129::get_start(outcome_data);
        //o.kernel_restart_cond;
        o.cvm = TAG_OUTCOME_PARAMETER_SET_DF8129::get_cvm(outcome_data);
        o.ui_request = static_cast<bool>(v_get_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::ui_request_on_outcome_present));
        o.ui_on_restart = static_cast<bool>(v_get_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::ui_request_on_restart_present));

        if (o.ui_request || o.ui_on_restart) {
            auto& v = db[USER_INTERFACE_REQUEST_DATA_DF8116];
            if (o.ui_request) {
                o.ui_request_data = TAG_USER_INTERFACE_REQUEST_DATA_DF8116::to_ui_req_data(v);
            } else {
                o.ui_restart_data = TAG_USER_INTERFACE_REQUEST_DATA_DF8116::to_ui_req_data(v);
            }
        };

        o.removal_timeout = TAG_OUTCOME_PARAMETER_SET_DF8129::get_removal_timerout(outcome_data);
        o.field_off_request = TAG_OUTCOME_PARAMETER_SET_DF8129::get_field_off(outcome_data);
        o.receipt = static_cast<bool>(v_get_bit(outcome_data, TAG_OUTCOME_PARAMETER_SET_DF8129::receipt_required));
        o.data_record_present = db.has_tag(DATA_RECORD_FF8105);
        if (o.data_record_present) {
            o.data_record = db[DATA_RECORD_FF8105];
        };

        o.discretionary_data_present = db.has_tag(DISCRETIONARY_DATA_FF8106);
        if (o.discretionary_data_present) {
            o.discretionary_data = db[DISCRETIONARY_DATA_FF8106];
        };

        return o;
#if 0
        OUTCOME_KERNEL_RESTART_COND kernel_restart_cond;
        INTERFACE_TYPE alt_interface;
        std::vector<uint8_t> data = output.serialize();
#endif
    };

    // post ui message
    outcome_builder& msg() {
        auto& v = db[USER_INTERFACE_REQUEST_DATA_DF8116];
#if 0
	pr_debug("..... Post Message .....\n");
        TAG_USER_INTERFACE_REQUEST_DATA_DF8116::print(ui_data, "\t");
#endif
        ui_req_data ui = TAG_USER_INTERFACE_REQUEST_DATA_DF8116::to_ui_req_data(v);
        send_ui_event(ui);
        return *this;
    };

    void print() {
        pr_debug("...... OUTCOME GENERATED ......\n");
        if (output.has_non_empty_tag(USER_INTERFACE_REQUEST_DATA_DF8116)) {
            output.print(USER_INTERFACE_REQUEST_DATA_DF8116);
            TAG_USER_INTERFACE_REQUEST_DATA_DF8116::print(output[USER_INTERFACE_REQUEST_DATA_DF8116], "\t");
        };

        if (output.has_non_empty_tag(OUTCOME_PARAMETER_SET_DF8129)) {
            output.print(OUTCOME_PARAMETER_SET_DF8129);
            TAG_OUTCOME_PARAMETER_SET_DF8129::print(output[OUTCOME_PARAMETER_SET_DF8129], "\t");
        }

        if (output.has_non_empty_tag(DATA_RECORD_FF8105)) {
            output.print(DATA_RECORD_FF8105);
            print_tlv_list(output[DATA_RECORD_FF8105], "\t");
        }

        if (output.has_non_empty_tag(DISCRETIONARY_DATA_FF8106)) {
            output.print(DISCRETIONARY_DATA_FF8106);
            print_tlv_list(output[DISCRETIONARY_DATA_FF8106], "\t");
        }
    }

    void print_tlv_list(const std::vector<uint8_t>& list, const std::string prefix = std::string{}) {
        auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) -> bool {
            (void)constructed;
            std::vector<uint8_t> v{begin, end};
            tlv_print(tag, v);
            return true;
        };
        tlv_visit(list.begin(), list.end(), parser);
    };

private:
    tlv_db& db;
    std::vector<uint8_t>& outcome_data;
    std::vector<uint8_t>& uintf;
    tlv_db output;
};

using AID = std::vector<uint8_t>;

struct preprocessing_indicator {
    preprocessing_indicator() {
        status_check_requested = false;
        contactless_not_allowed = false;
        zero_amount = false;
        reader_cvm_required_limit_exceeded = false;
        reader_contactless_floor_limit_exeeded = false;
    };

    bool status_check_requested;
    bool contactless_not_allowed;
    bool zero_amount;
    bool reader_cvm_required_limit_exceeded;
    bool reader_contactless_floor_limit_exeeded;
    std::optional<std::vector<uint8_t>> ttq;
};

using AID = std::vector<uint8_t>;

struct transaction_cfg {
    AID aid;
    TRANSACTION_TYPE transact_type;
    std::optional<bool> status_check_support;
    std::optional<bool> zero_amount_allowed;
    std::optional<unsigned int> reader_contactless_transaction_limit;
    std::optional<unsigned int> reader_contactless_floor_limit;
    std::optional<unsigned int> terminal_floor_limit_9F1B;
    std::optional<unsigned int> reader_cvm_required_limit;
    std::optional<bool> extended_selection_support;
    tlv_db db;
};

struct application_cfg {
    AID aid;
    tlv_db db;
    std::vector<transaction_cfg> tr_cfgs;
};

struct kernel_cfg {
    KERNEL_ID kid;
    int terminalEntryCapability;
    bool fddaForOnlineSupported;
    bool displayAvailableSpendingAmount;
    bool aucManualCheckSupported;
    bool aucCashbackCheckSupported;
    bool atmOfflineCheck;
    bool exceptionFileEnabled;
    tlv_db db;
    std::vector<application_cfg> app_cfgs;
};

struct cakey {
    uint8_t hashAlgorithmIndicator;
    uint8_t publicKeyAlgorithmIndicator;
    std::vector<uint8_t> modulus;
    std::vector<uint8_t> exponent;
    std::string expiryDate;
    uint8_t index;
    std::vector<uint8_t> checksum;
    std::vector<uint8_t> rid;
};

struct reader_cfg {
    std::string name;
    tlv_db terminal_cfg;
    std::vector<kernel_cfg> kernel_cfgs;
    std::vector<cakey> pks;
    std::unordered_set<std::string> exceptions;
    void print() const {
        pr_debug("<--  config ", name, "  -->\n");
        pr_debug("<terminal>\n");
        terminal_cfg.print(std::string("\t"));
        for (auto& kcfg : kernel_cfgs) {
            pr_debug("<kernel ", static_cast<int>(kcfg.kid), " >\n");
            auto backup = active_kernel_tag_set;
            active_kernel_tag_set = (kcfg.kid == KERNEL_ID::KERNEL_2) ? &KERNEL2_NS::all_tags_set : &KERNEL3_NS::all_tags_set;
            kcfg.db.print("\t");
            for (auto& app : kcfg.app_cfgs) {
                pr_debug("\t<aid ", app.aid, " >\n");
                app.db.print(std::string("\t\t"));
                for (auto& tr : app.tr_cfgs) {
                    pr_debug("\t\t<transaction type ", static_cast<int>(tr.transact_type), " >\n");
                    tr.db.print(std::string("\t\t\t"));
                };
            };
            active_kernel_tag_set = backup;
        };
    };
};

using issuer_script = std::vector<uint8_t>;

struct combination {
    combination(KERNEL_ID kid, AID aid) : aid(aid), kid(kid){};
    AID aid;
    KERNEL_ID kid;
    const kernel_cfg* krn;
    const application_cfg* app;
    const transaction_cfg* transact;
    tlv_db db; // dynamic db vs static above
    preprocessing_indicator indicator;
};

struct candidate {
    std::vector<uint8_t> adf_name;
    std::vector<uint8_t> extended_selection;
    uint8_t priority;
    uint8_t order;
    const combination* combo;
};

class modulel2;

class kernel {
public:
    virtual bool start(uint8_t sw1, uint8_t sw2, const tlv_db fci, const candidate* candy, const issuer_script script, modulel2* l2) = 0;
};

class kernel_factory {
public:
    virtual kernel* get_kernel(KERNEL_ID kid) = 0;
};

extern kernel_factory* emv_kernel_factory;

class modulel2 : public emv_module {
public:
    class responder {
    public:
        responder(int msecs, modulel2* emvl2) : emvl2(emvl2) {
            tm = emv_timer_factory->create(msecs, [&]() { timeout(); });
        };
        void start_timer(int msecs = 0) {
            if (msecs != 0) {
                tm->set_duration(msecs);
            }
            tm->start();
        };

        void stop_timer() {
            tm->stop();
        };
        virtual void handle_apdu(const std::vector<uint8_t>& apdu) {
            tm->stop();
        };
        virtual void handle_det(const std::vector<uint8_t>& data){};
        virtual void handle_l1rsp(const std::vector<uint8_t>& error){};
        virtual void timeout(){};
        virtual ~responder(){};

        // override the behavior in derived class
        // if you don't want to start timer by default on entering
        virtual void enter() {
            tm->start();
        };
        virtual void exit() {
            tm->stop();
        }

    protected:
        std::unique_ptr<timer> tm;
        modulel2* emvl2;
    };

    virtual bool are_you(EMV_MODULE who) const override {
        return who == EMV_MODULE::L2;
    };

private:
    class default_responder : public responder {
    public:
        default_responder(modulel2* emvl2) : responder(0, emvl2){};
        virtual void handle_apdu(const std::vector<uint8_t>& apdu) override {
            pr_error("UNEXPECTED APDU RECEIVED IN DEFAULT STATE\n");
        };
        virtual void timeout() override{};
    };

    class select_aid_responder : public responder {
    private:
        struct response_parser {
            bool operator()(uint32_t tag, std::vector<uint8_t>::const_iterator begin,
                            std::vector<uint8_t>::const_iterator end, bool constructed) {
                if (constructed)
                    return true;

                std::vector<uint8_t> v{begin, end};
                tlv_print(tag, v);
                tlv_obj obj{tag, v};
                active_kernel_tag_set = (kid == KERNEL_ID::KERNEL_2 ? &KERNEL2_NS::all_tags_set : &KERNEL3_NS::all_tags_set);
                fci.insert(obj);
                return true;
            };

            tlv_db fci;
            KERNEL_ID kid;
        };

    public:
        select_aid_responder(modulel2* emvl2) : responder(1000, emvl2){};
        virtual void handle_apdu(const std::vector<uint8_t>& apdu) override {
            responder::handle_apdu(apdu);
            pr_debug("handle select aid response\n");
            auto parser = response_parser{};
            parser.kid = last_choice->combo->kid;
            if (apdu.size() < 2) {
                // TODO
                return;
            };

            bool ret = tlv_visit(apdu.begin(), apdu.end() - 2, parser);
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            if (ret) {
                emvl2->select_kernel(sw1, sw2, parser.fci);
            } else {
                // TODO
            };
        };

    public:
        std::list<candidate>::iterator last_choice;
    };

    class ppse_responder : public responder {
    private:
        struct response_parser {
            bool have_fci_template_6F;
            bool have_fci_template_A5;
            bool have_df_name_84;
            bool have_discretionary_data_BF0C;
            std::vector<tlv_db> apps;

            bool operator()(uint32_t tag, std::vector<uint8_t>::const_iterator begin,
                            std::vector<uint8_t>::const_iterator end, bool constructed) {
                if (tag == 0x6F) {
                    have_fci_template_6F = true;
                } else if (tag == 0x84) {
                    if (!have_fci_template_6F) {
                        return false;
                    }
                    have_df_name_84 = true;
                    // check it is PPSE
                    std::string ppse = "2PAY.SYS.DDF01";
                    int index = 0;
                    for (auto p = begin; p != end; p++) {
                        if (*p != ppse[index++]) {
                            logger.error("did not find correct ppse\n");
                            return false;
                        }
                    }
                } else if (tag == 0xA5) {
                    if (!have_df_name_84)
                        return false;
                    have_fci_template_A5 = true;
                } else if (tag == 0xBF0C) {
                    if (!have_fci_template_A5)
                        return false;
                    have_discretionary_data_BF0C = true;
                } else if (tag == 0x61) {
                    if (!have_discretionary_data_BF0C)
                        return false;
                    apps.resize(apps.size() + 1);
                } else if (tag == 0x4F) {
                    std::vector<uint8_t> adf_name{begin, end};
                    pr_debug("ADF name : ", adf_name, "\n");
                    tlv_db& current = apps[apps.size() - 1];
                    current.emplace(0x4FU, std::move(adf_name));
                } else if (tag == 0x50) {
                    std::vector<uint8_t> label{begin, end};
                    std::string name;
                    for (auto p = begin; p != end; p++) {
                        name.push_back(*p);
                    }
                    pr_debug("label : ", name, "\n");
                    tlv_db& current = apps[apps.size() - 1];
                    current.emplace(0x50U, std::move(label));
                } else if (tag == 0x87) {
                    tlv_db& current = apps[apps.size() - 1];
                    current.emplace(0x87U, std::vector<uint8_t>{begin, end});
                }
                return true;
            };
        };

    public:
        ppse_responder(modulel2* emvl2) : responder(1000, emvl2){};
        virtual void handle_apdu(const std::vector<uint8_t>& apdu) override {
            responder::handle_apdu(apdu);
            pr_debug("handling ppse response\n");
            if (apdu.size() < 2) {
                // TODO
                return;
            }
            uint8_t sw1 = apdu[apdu.size() - 2];
            uint8_t sw2 = apdu[apdu.size() - 1];
            auto parser = response_parser{};
            bool ret = tlv_visit(apdu.begin(), apdu.end() - 2, parser);
            if (ret) {
                emvl2->prepare_candidates(sw1, sw2, parser.apps);
            } else {
                // TODO
            }
        };
    };

public:
    modulel2(const reader_cfg& cfgs) : emv_module{},
                                       retained_restart_ui_present{false},
                                       issuer_script_avail{false},
                                       retained_condition{OUTCOME_KERNEL_RESTART_COND::NA},
                                       l2_cfgs(cfgs),
                                       state_default{default_responder{this}},
                                       state_wait_for_ppse{ppse_responder{this}},
                                       l2_state(&state_default),
                                       state_wait_for_select_aid{select_aid_responder{this}} {
        field_off_timer = emv_timer_factory->create(0, [&]() {
            message out{MESSAGE_ID::L1_POWER_UP, EMV_MODULE::L2, EMV_MODULE::L1};
            out.send();
        });
    };

    void send_apdu(const std::vector<uint8_t>& apdu) {
        pr_debug("send apdu : ", apdu, "\n");
        message out{MESSAGE_ID::L1_TX_DATA, EMV_MODULE::L2, EMV_MODULE::L1, apdu};
        out.send();
    };

    virtual void handle_message(const message& msg) override {
        auto id = msg.get_message_id();
        switch (id) {
        case MESSAGE_ID::L1_CARD_DETECTED: {
            pr_debug("receiving L1 card detected\n");
            auto body = msg.get_body();
            if (body.size() >= 2) {
                enter_express_mode(body);
                return;
            };
            start_combination_selection();
            break;
        };

        case MESSAGE_ID::L1_COLLISION_DETECTED: {
            pr_debug("Receiving L1 collision detection\n");
            // 3.2.1.4
            ui_req_data ui;
            ui.ui_id = ui_message_id::PRESENT_ONE_ONLY;
            ui.status = ui_status_id::COLLISION_ERR;
            send_ui_event(ui);
            break;
        }

        case MESSAGE_ID::L2_CONTINUE_TRANSACT_WITH_ONLINE_RESP: {
            pr_debug("L2 get online response\n");
            bool have_scripts = false;
            auto parser = [&have_scripts](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                (void)begin;
                (void)end;
                if (constructed && (tag == 0x71 || tag == 0x72)) {
                    have_scripts = true;
                };
                return true;
            };
            tlv_visit(msg.body_begin(), msg.body_end(), parser);
            if (whence == RESTART_POINT::B) {
                if ((retained_condition == OUTCOME_KERNEL_RESTART_COND::EMV_DATA_AVAIL && have_scripts) ||
                    retained_condition == OUTCOME_KERNEL_RESTART_COND::ANY) {
                    issuer_script_avail = true;
                    issuer_update_scripts = msg.get_body();
                    pr_debug("restart from B for online response\n");
                    protocol_activation(true);
                    break;
                }
            }

            message out{MESSAGE_ID::TERMINAL_TRANSACTION_COMPLETE,
                        EMV_MODULE::L2,
                        EMV_MODULE::TERMINAL};
            out.send();

            break;
        };

        case MESSAGE_ID::L1_DATA_RECEIVED: {
            auto body = msg.get_body();
            pr_debug("receiving APDU ", body, "\n");
            l2_state->handle_apdu(body);
            break;
        }

        case MESSAGE_ID::L1RSP: {
            auto body = msg.get_body();
            pr_debug("receiving L1RSP ", body, "\n");
            l2_state->handle_l1rsp(body);
            break;
        };

        case MESSAGE_ID::DET: {
            auto body = msg.get_body();
            pr_debug("receive DET ", body, "\n");
            l2_state->handle_det(body);
            break;
        }

        case MESSAGE_ID::L2_START_TRANSACTION: {
            auto body = msg.get_body();
            logger.info("receiving L2 start transaction: ", body, "\n");
            tlv_db transaction_req{};
            transaction_req.parse(body);

            ///check the mandatory elements
            if (transaction_req.has_tag(TRANSACTION_DATE_9A) &&
                transaction_req.has_tag(TRANSACTION_TIME_9F21) &&
                transaction_req.has_tag(UNPREDICTABLE_NUMBER_9F37)) {
                start_transaction(transaction_req);
            }
            else
            {
                pr_error("fatal error, mandatory TLV missing from transaction request!!!\n");
                transaction_req.print();
                throw std::bad_exception();
            }
            break;
        }
        default:
            break;
        }
    };

    void generate_outcome(const outcome& o) {
        set_state(&state_default);

        logger.info("Generated outcome\n");
        logger << o;

        issuer_script_avail = false;
        issuer_update_scripts.clear();
        whence = o.start;

        // 3.5.1.1
        if (o.ui_request) {
            send_ui_event(o.ui_request_data);
        }
        retained_restart_ui_present = o.ui_on_restart;
        if (retained_restart_ui_present)
            retained_restart_ui = o.ui_restart_data;
        retained_condition = o.kernel_restart_cond;

        // 3.5.1.2
        if (o.field_off_request >= 0) {
            message out{MESSAGE_ID::L1_POWER_DOWN, EMV_MODULE::L2, EMV_MODULE::L1};
            out.send();

            if (o.field_off_request > 0) {
                field_off_timer->set_duration(o.field_off_request * 100);
                field_off_timer->start();
            }
        };

        switch (o.type) {
        case OUTCOME_TYPE::SELECT_NEXT: // 3.5.1.4
            whence = RESTART_POINT::C;
            candidates.erase(state_wait_for_select_aid.last_choice);
            state_wait_for_select_aid.last_choice = candidates.begin();
            // goto 3.3.2.6
            select_combination();
            break;
        case OUTCOME_TYPE::TRY_AGAIN: // 3.5.1.3
            whence = RESTART_POINT::B;
            // goto 3.2.1
            protocol_activation(false);
            break;
        case OUTCOME_TYPE::APPROVED:
        case OUTCOME_TYPE::ONLINE_REQUEST: {
            whence = o.start;
            std::vector<uint8_t> data{static_cast<uint8_t>(o.cvm)};
            std::copy(o.data_record.begin(), o.data_record.end(), back_inserter(data));
            if (o.discretionary_data_present) {
                std::copy(o.discretionary_data.cbegin(), o.discretionary_data.cend(),
                          back_inserter(data));
            };
            message out{(o.type == OUTCOME_TYPE::ONLINE_REQUEST) ? MESSAGE_ID::TERMINAL_ONLINE_REQ : MESSAGE_ID::TERMINAL_TRANSACTION_COMPLETE,
                        EMV_MODULE::L2,
                        EMV_MODULE::TERMINAL,
                        data};
            out.send();
            break;
        }

        case OUTCOME_TYPE::DECLINED:
        case OUTCOME_TYPE::TRY_ANOTHER_INTERFACE:
        case OUTCOME_TYPE::END_APPLICATION:
            // 3.5.1.5
            // present result to reader
            // TODO
            break;
        default:
            break;
        }
    };

    void set_state(responder* state = nullptr) {
        if (state == nullptr)
            state = &state_default;

        if (state != l2_state) {
            l2_state->exit();
            l2_state = state;
            l2_state->enter();
        }
    };

    const cakey* find_ca_key(const std::vector<uint8_t>& rid, uint8_t index) const {
        pr_debug("look for ca key, rid ", rid, " index ", to_hex((uint32_t)index), "\n");
        for (auto& p : l2_cfgs.pks) {
            if (p.index == index && p.rid == rid) {
                pr_debug("modulus ", p.modulus, "[", p.modulus.size(), " bytes ]\n");
                return &p;
            }
        };

        return nullptr;
    };

    bool found_on_exceptions(const std::string& pan) const {
        return (l2_cfgs.exceptions.find(pan) != l2_cfgs.exceptions.end());
    };

    bool verify_sda(tlv_db& db, const cakey* cak,
                    const std::vector<uint8_t>& ssad, const std::vector<uint8_t>& static_data) {
        std::vector<uint8_t> issuer_modulus{};
        if (!verify_issuer(db, cak, issuer_modulus)) {
            return false;
        }

        if (!verify_ssad(db, ssad, issuer_modulus, static_data)) {
            return false;
        };

        return true;
    };

    bool verify_ssad(tlv_db& db, const std::vector<uint8_t>& ssad, const std::vector<uint8_t>& issuer_modulus,
                     const std::vector<uint8_t>& static_data) {
        pr_debug("verify ssad\n");
        if (ssad.size() != issuer_modulus.size()) {
            pr_debug("ssad not the same size as issuer modulus\n");
            return false;
        }

        std::vector<uint8_t> recovered(issuer_modulus.size());
        bignum_exp_modulus(ssad, db[ISSUER_PUB_KEY_EXP_9F32], issuer_modulus, recovered);
        //pr_debug("recovered ssad\n", recovered, "\n");
        if (recovered[0] != 0x6A ||                    // header
            recovered[recovered.size() - 1] != 0xBC || // trailer
            recovered[1] != 0x03) {                    // format
            pr_debug("recovered icc cert format wrong\n");
            return false;
        }

        int size = recovered.size() - 22;
        auto begin = recovered.cbegin() + 1;
        std::vector<uint8_t> input{begin, begin + size};
        std::copy(static_data.begin(), static_data.end(), back_inserter(input));

        if (db.has_non_empty_tag(SDA_TAG_LIST_9F4A.id)) {
            auto& tag_list = db[SDA_TAG_LIST_9F4A];
            if (tag_list.size() != 1 || tag_list[0] != AIP_82.id) {
                pr_error("SDA TAG LIST does not contain 0x82 only\n");
                return false;
            };
            auto& aip = db[AIP_82];
            std::copy(aip.begin(), aip.end(), back_inserter(input));
        };

        std::vector<uint8_t> hash(20);
        compute_sha1(input.data(), input.size(), hash.data());

        auto hash_begin = recovered.cbegin() + (recovered.size() - 21);
        std::vector<uint8_t> expect{hash_begin, hash_begin + 20};
        if (hash != expect) {
            pr_error("ssad hash not equal\n");
            pr_debug("expect ", expect, "\nactual ", hash, "\n");
            return false;
        }

        tlv_obj tlv{DATA_AUTHENTICATION_CODE_9F45.id, std::vector<uint8_t>{recovered.cbegin() + 3, recovered.cbegin() + 5}};
        db.insert(std::move(tlv));

        return true;
    };

    bool verify_dda(tlv_db& db,
                    const cakey* cak,
                    const std::vector<uint8_t>& sig,
                    const std::vector<uint8_t>& static_data,
                    const std::vector<uint8_t>& ddol) {
        std::vector<uint8_t> issuer_modulus{};
        if (!verify_issuer(db, cak, issuer_modulus)) {
            return false;
        }

        std::vector<uint8_t> icc_modulus{};
        if (!verify_icc(db, issuer_modulus, static_data, icc_modulus)) {
            return false;
        }

        if (!verify_sdad(db, sig, icc_modulus, ddol)) {
            return false;
        }

        return true;
    };

    static bool get_rid(const tlv_db& db, std::vector<uint8_t>& rid) {
        if (db.has_tag(ADF_NAME_4F)) {
            auto& p = db[ADF_NAME_4F];
            std::copy(p.begin(), p.begin() + 5, back_inserter(rid));
            return true;
        }

        return false;
    };

    bool retrieve_icc_pk(const tlv_db& db, std::vector<uint8_t>& icc_modulus, std::vector<uint8_t>& static_data) {
        if (!db.has_tag(CA_PUBLIC_KEY_INDEX_8F)) {
            pr_debug("missing tag 8F\n");
            return false;
        };

        std::vector<uint8_t> rid{};
        if (!get_rid(db, rid))
            return false;

        auto cak = find_ca_key(rid, db(CA_PUBLIC_KEY_INDEX_8F));
        if (cak == nullptr) {
            pr_debug("sorry, missing ca key\n");
            return false;
        }

        std::vector<uint8_t> issuer_modulus{};
        if (!verify_issuer(db, cak, issuer_modulus)) {
            return false;
        }

        if (!verify_icc(db, issuer_modulus, static_data, icc_modulus)) {
            return false;
        }

        return true;
    }

    bool verify_cda(tlv_db& db, std::vector<uint8_t>& icc_modulus,
                    const std::vector<uint8_t>& apdu, bool extract_extra = false) {
        pr_debug("verify cda\n");
        if (!db.has_tag(SDAD_9F4B)) {
            pr_debug("tag missing\n");
            return false;
        }

        auto& sig = db[SDAD_9F4B];

        if (icc_modulus.size() != sig.size()) {
            pr_error("sig size ", sig.size(), " does not match icc modulus size ", icc_modulus.size(), "\n");
            return false;
        }

        std::vector<uint8_t> recovered(icc_modulus.size());
        bignum_exp_modulus(sig, db[ICC_PUB_KEY_EXP_9F47], icc_modulus, recovered);
        //pr_debug("recovered signature\n", recovered, "\n");
        if (recovered[0] != 0x6A ||                    // header
            recovered[recovered.size() - 1] != 0xBC || // trailer
            recovered[1] != 0x05) {                    // format
            pr_debug("recovered signature format wrong\n");
            return false;
        }

        int size = recovered.size() - 22;
        auto begin = recovered.cbegin() + 1;
        std::vector<uint8_t> input{begin, begin + size};
        auto un = db[UNPREDICTABLE_NUMBER_9F37];
        std::copy(un.cbegin(), un.cend(), back_inserter(input));
        std::vector<uint8_t> hash(20);
        compute_sha1(input.data(), input.size(), hash.data());

        auto hash_begin = recovered.cbegin() + (recovered.size() - 21);
        std::vector<uint8_t> expect{hash_begin, hash_begin + 20};
        if (hash != expect) {
            pr_error("sdad hash not equal\n");
            pr_debug("expect ", expect, "\nactual ", hash, "\n");
            return false;
        }

        std::vector<uint8_t> dynamic_data{recovered.cbegin() + 4, recovered.cbegin() + 4 + recovered[3]};
        //pr_debug("dynamic data : ", dynamic_data, "\n");

        if (static_cast<unsigned int>(dynamic_data[0] + 30) > dynamic_data.size()) {
            pr_error("dynamic size not correct\n");
            return false;
        }

        auto dn_size = dynamic_data[0];
        std::vector<uint8_t> dn{dynamic_data.cbegin() + 1, dynamic_data.cbegin() + 1 + dn_size};
        //pr_debug("dynamic number : ", dn, "\n");
        auto cid = dynamic_data[dn_size + 1];
        if (cid != db[CID_9F27][0]) {
            pr_debug("CID in cryptogram not equal to what is sent\n");
            return false;
        }

        std::vector<uint8_t> tr_data_hash{dynamic_data.cbegin() + dn_size + 2 + 8, dynamic_data.cbegin() + dn_size + 2 + 8 + 20};
        if (!verify_transact_data(db, apdu, tr_data_hash)) {
            return false;
        }

        std::vector<uint8_t> cryptogram{dynamic_data.cbegin() + dn_size + 2, dynamic_data.cbegin() + dn_size + 2 + 8};
        //pr_debug("cryptogram : ", cryptogram, "\n");

        db.insert(tlv_obj{ICC_DYNAMIC_NUMBER_9F4C.id, dn});
        db.insert(tlv_obj{APPLICATION_CRYPTOGRAM_9F26.id, cryptogram});

        if (extract_extra) {
            // the extra dynamic data might be needed for RRP or IDS (contactless kernel 2)
            std::vector<uint8_t> extra_dynamic_data{dynamic_data.cbegin() + dn_size + 2 + 8 + 20, dynamic_data.cend()};
            return cda_extract_data(db, extra_dynamic_data);
        }

        return true;
    }

    // procedure defined in emv contactless kernel 2
    // S910 or S11
    bool cda_extract_data(tlv_db& db, std::vector<uint8_t>& extra) {
        if (db.get_bit(IDS_STATUS_DF8128, TAG_IDS_STATUS_DF8128::read)) {
            // S910.2.2
            auto& cap = db[KERNEL2::APPLICATION_CAPABILITIES_INFO_9F5D];
            auto ver = KERNEL2::TAG_APPLICATION_CAPABILITIES_INFO_9F5D::get_ds_version(cap);
            uint8_t summary_size = (ver == 1) ? 8 : 16;
            if (TAG_TVR_95::get_rrp(db[TVR_95]) == TAG_TVR_95::RRP_STATUS::PERFORMED) {
                // S910.3.1
                pr_debug("handle cda ids-rrp\n");
                if ((ver == 1 && extra.size() >= 30) ||
                    (ver == 2 && extra.size() >= 46)) {
                    auto begin = extra.cbegin();
                    std::vector<uint8_t> summary2{begin, begin + summary_size};
                    begin += summary_size;
                    db.insert(tlv_obj{DS_SUMMARY_2_DF8101.id, std::move(summary2)});
                    std::vector<uint8_t> summary3{begin, begin + summary_size};
                    begin += summary_size;
                    db.insert(tlv_obj{DS_SUMMARY_3_DF8102.id, std::move(summary3)});
                    std::vector<uint8_t> term_entropy{begin, begin + 4};
                    begin += 4;
                    std::vector<uint8_t> dev_entropy{begin, begin + 4};
                    begin += 4;
                    std::vector<uint8_t> min_time{begin, begin + 2};
                    begin += 2;
                    std::vector<uint8_t> max_time{begin, begin + 2};
                    begin += 2;
                    std::vector<uint8_t> estimated{begin, begin + 2};
                    if (term_entropy == db[TERMINAL_RELAY_RESISTENCE_ENTROPY_DF8301] &&
                        dev_entropy == db[DEVIDE_REPLAY_RESISTENCE_ENTROPY_DF8302] &&
                        min_time == db[MIN_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8303] &&
                        max_time == db[MAX_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8304] &&
                        estimated == db[DEVICE_ESTIMATED_TRANSMISSION_TIME_DF8305]) {
                        return true;
                    }
                }
            } else {
                // S910.3
                pr_debug("handle cda - ids\n");
                auto begin = extra.cbegin();
                if (begin + summary_size <= extra.cend()) {
                    std::vector<uint8_t> summary2{begin, begin + summary_size};
                    begin += summary_size;
                    db.insert(tlv_obj{DS_SUMMARY_2_DF8101.id, std::move(summary2)});
                    if (begin + summary_size <= extra.cend()) {
                        std::vector<uint8_t> summary3{begin, begin + summary_size};
                        begin += summary_size;
                        db.insert(tlv_obj{DS_SUMMARY_3_DF8102.id, std::move(summary3)});
                    }
                }
                return true;
            }
        } else {
            // S910.2.1
            if (TAG_TVR_95::get_rrp(db[TVR_95]) == TAG_TVR_95::RRP_STATUS::PERFORMED) {
                // S910.4.1
                pr_debug("handle cda - rrp\n");
                if (extra.size() >= 14) {
                    auto begin = extra.cbegin();
                    std::vector<uint8_t> term_entropy{begin, begin + 4};
                    begin += 4;
                    std::vector<uint8_t> dev_entropy{begin, begin + 4};
                    begin += 4;
                    std::vector<uint8_t> min_time{begin, begin + 2};
                    begin += 2;
                    std::vector<uint8_t> max_time{begin, begin + 2};
                    begin += 2;
                    std::vector<uint8_t> estimated{begin, begin + 2};
                    if (term_entropy == db[TERMINAL_RELAY_RESISTENCE_ENTROPY_DF8301] &&
                        dev_entropy == db[DEVIDE_REPLAY_RESISTENCE_ENTROPY_DF8302] &&
                        min_time == db[MIN_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8303] &&
                        max_time == db[MAX_TIME_PROCESSING_RELAY_RESISTENCE_APDU_DF8304] &&
                        estimated == db[DEVICE_ESTIMATED_TRANSMISSION_TIME_DF8305]) {
                        return true;
                    }
                }
            } else {
                // S910.4
                pr_debug("handle cda - default\n");
                return true;
            }
        }

        return false;
    };

    bool verify_transact_data(const tlv_db& db, const std::vector<uint8_t>& apdu, const std::vector<uint8_t>& tr_data_hash) {
        // verify the transaction data hash
        pr_debug("verify transaction data\n");
        std::vector<uint8_t> input{};

        auto& pdol_related_data = db[PDOL_RELATED_DATA_DF8111];
        std::copy(pdol_related_data.begin(), pdol_related_data.end(),
                  back_inserter(input));
        auto& cdol1_related_data = db[CDOL1_RELATED_DATA_DF8107];
        std::copy(cdol1_related_data.begin(), cdol1_related_data.end(),
                  back_inserter(input));

        auto parser = [&](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
            if (!constructed && tag != SDAD_9F4B.id) {
                std::vector<uint8_t> v{begin, end};
                auto tlv = make_tlv(tag, v);
                std::copy(tlv.begin(), tlv.end(), back_inserter(input));
            }
            return true;
        };

        if (!tlv_visit(apdu.cbegin(), apdu.cend() - 2, parser)) {
            pr_debug("gac apdu parse errror\n");
            return false;
        }

        std::vector<uint8_t> hash(20);
        compute_sha1(input.data(), input.size(), hash.data());
        if (hash != tr_data_hash) {
            pr_debug("pdol ", pdol_related_data, "\n");
            pr_debug("codl1 ", cdol1_related_data, "\n");
            pr_debug("apdu ", apdu, "\n");
            pr_debug("hash not match for transact data: ", input, "\n");
            pr_debug("expect ", tr_data_hash, " actual ", hash, "\n");
            return false;
        }

        return true;
    }

    bool verify_sdad(tlv_db& db, const std::vector<uint8_t>& sig, std::vector<uint8_t>& icc_modulus, const std::vector<uint8_t>& ddol) {
        pr_debug("verify sdad\n");
        if (icc_modulus.size() != sig.size()) {
            pr_error("sig size ", sig.size(), " does not match icc modulus size ", icc_modulus.size(), "\n");
            return false;
        }

        std::vector<uint8_t> recovered(icc_modulus.size());
        bignum_exp_modulus(sig, db[ICC_PUB_KEY_EXP_9F47], icc_modulus, recovered);
        //pr_debug("recovered signature\n", recovered, "\n");
        if (recovered[0] != 0x6A ||                    // header
            recovered[recovered.size() - 1] != 0xBC || // trailer
            recovered[1] != 0x05) {                    // format
            pr_debug("recovered signature format wrong\n");
            return false;
        }

        int size = recovered.size() - 22;
        auto begin = recovered.cbegin() + 1;
        std::vector<uint8_t> input{begin, begin + size};
        std::copy(ddol.cbegin(), ddol.cend(), back_inserter(input));
        std::vector<uint8_t> hash(20);
        compute_sha1(input.data(), input.size(), hash.data());

        auto hash_begin = recovered.cbegin() + (recovered.size() - 21);
        std::vector<uint8_t> expect{hash_begin, hash_begin + 20};
        if (hash != expect) {
            pr_error("sdad hash not equal\n");
            pr_debug("expect ", expect, "\nactual ", hash, "\n");
            return false;
        }

        tlv_obj tlv{ICC_DYNAMIC_NUMBER_9F4C.id, std::vector<uint8_t>{recovered.cbegin() + 4, recovered.cbegin() + 4 + recovered[3]}};
        db.insert(std::move(tlv));
        return true;
    };

    bool verify_icc(const tlv_db& db, std::vector<uint8_t>& issuer_modulus, const std::vector<uint8_t>& static_data,
                    std::vector<uint8_t>& icc_modulus) {
        pr_debug("verify icc\n");
        auto& cert = db[ICC_PUB_KEY_CERT_9F46];
        if (cert.size() != issuer_modulus.size()) {
            pr_error("wrong icc cert size ", cert.size(), " expect ", issuer_modulus.size(), "\n");
            return false;
        }

        std::vector<uint8_t> recovered(issuer_modulus.size());
        bignum_exp_modulus(cert, db[ISSUER_PUB_KEY_EXP_9F32], issuer_modulus, recovered);
        //pr_debug("recovered icc cert\n", recovered, "\n");
        if (recovered[0] != 0x6A ||                    // header
            recovered[recovered.size() - 1] != 0xBC || // trailer
            recovered[1] != 0x04) {                    // format
            pr_debug("recovered icc cert format wrong\n");
            return false;
        }

        int size = recovered.size() - 22;
        auto begin = recovered.cbegin() + 1;
        std::vector<uint8_t> input{begin, begin + size};
        std::vector<uint8_t> pubkey{recovered.cbegin() + 21, recovered.cbegin() + (recovered.size() - 21)};
        if (db.has_tag(ICC_PUB_KEY_REMAINER_9F48)) {
            auto& p = db[ICC_PUB_KEY_REMAINER_9F48];
            std::copy(p.begin(), p.end(), back_inserter(input));
            std::copy(p.begin(), p.end(), back_inserter(pubkey));
        };
        pr_debug("icc pub key ", pubkey, " size ", (int)pubkey.size(), "\n");
        pr_debug("indicated pk size ", static_cast<int>(recovered[19]), " exp size ", static_cast<int>(recovered[20]), "\n");

        auto& e = db[ICC_PUB_KEY_EXP_9F47];
        std::copy(e.begin(), e.end(), back_inserter(input));
        std::copy(static_data.begin(), static_data.end(), back_inserter(input));

        if (db.has_non_empty_tag(SDA_TAG_LIST_9F4A.id)) {
            auto& tag_list = db[SDA_TAG_LIST_9F4A];
            if (tag_list.size() != 1 || tag_list[0] != AIP_82.id) {
                pr_error("SDA TAG LIST does not contain 0x82 only\n");
                return false;
            };
            auto& aip = db[AIP_82];
            std::copy(aip.begin(), aip.end(), back_inserter(input));
        };

        std::vector<uint8_t> hash(20);
        compute_sha1(input.data(), input.size(), hash.data());

        auto hash_begin = recovered.cbegin() + (recovered.size() - 21);
        std::vector<uint8_t> expect{hash_begin, hash_begin + 20};
        if (hash != expect) {
            pr_error("icc hash not equal\n");
            pr_debug("expect ", expect, "\nactual ", hash, "\n");
            return false;
        }

        auto pan1 = PAN_5A.to_string(std::vector<uint8_t>{recovered.cbegin() + 2, recovered.cbegin() + 12});
        std::string pan2{};

        if (db.has_tag(TRACK2_57)) {
            pan2 = TRACK2_57.get_pan(db[TRACK2_57]);
        } else {
            pan2 = db(PAN_5A);
        }

        if (pan1 != pan2) {
            pr_debug("pan in the cert ", pan1, " different from ", pan2, "\n");
            return false;
        }

        auto& today = db[TRANSACTION_DATE_9A];
        std::vector<uint8_t> date{recovered.cbegin() + 12, recovered.cbegin() + 14}; // MMYY
        if (date[1] < today[0] || (date[1] == today[0] && date[0] < today[1])) {
            pr_debug("icc certificate date ", date, " expired, today ", today, "\n");
            return false;
        }

        if (recovered[17] != 0x01 || recovered[18] != 0x01) {
            pr_debug("public key or hash algorithm not correct\n");
            return false;
        }

        pubkey.resize(static_cast<int>(recovered[19]));
        icc_modulus.swap(pubkey);

        return true;
    };

    bool verify_issuer(const tlv_db& db, const cakey* cak, std::vector<uint8_t>& issuer_modulus) {
        pr_debug("verify issuer\n");
        auto& cert = db[ISSUER_PUB_KEY_CERT_90];
        if (cert.size() != cak->modulus.size()) {
            pr_error("wrong issuer cert size ", cert.size(), " expect ", cak->modulus.size(), "\n");
            return false;
        }

        std::vector<uint8_t> recovered(cak->modulus.size());
        bignum_exp_modulus(cert, cak->exponent, cak->modulus, recovered);
        //pr_verbose("recovered issuer cert\n", recovered, "\n");
        if (recovered[0] != 0x6A ||                    // header
            recovered[recovered.size() - 1] != 0xBC || // trailer
            recovered[1] != 0x02) {                    // format
            pr_debug("recovered issuer cert format wrong\n");
            return false;
        }

        int size = recovered.size() - 22;
        auto begin = recovered.cbegin() + 1;
        std::vector<uint8_t> input{begin, begin + size};

        std::vector<uint8_t> pubkey{recovered.cbegin() + 15, recovered.cbegin() + (recovered.size() - 21)};
        if (db.has_tag(ISSUER_PUB_KEY_REMAINER_92)) {
            auto& p = db[ISSUER_PUB_KEY_REMAINER_92];
            std::copy(p.begin(), p.end(), back_inserter(input));
            std::copy(p.begin(), p.end(), back_inserter(pubkey));
        };

        auto& e = db[ISSUER_PUB_KEY_EXP_9F32];
        std::copy(e.begin(), e.end(), back_inserter(input));

        if (cak->hashAlgorithmIndicator != 0x01) {
            pr_error("hash algorithm ", static_cast<int>(cak->hashAlgorithmIndicator), " not supported\n");
            return false;
        }

        std::vector<uint8_t> hash(20);
        compute_sha1(input.data(), input.size(), hash.data());

        auto hash_begin = recovered.cbegin() + (recovered.size() - 21);
        std::vector<uint8_t> actual{hash_begin, hash_begin + 20};
        if (hash != actual) {
            pr_error("hash not equal\n");
            return false;
        }

        auto issuer_id = PAN_5A.to_string(std::vector<uint8_t>{recovered.cbegin() + 2, recovered.cbegin() + 6});
        std::string pan{};
        if (db.has_tag(TRACK2_57)) {
            pan = TRACK2_57.get_pan(db[TRACK2_57]);
        } else {
            pan = db(PAN_5A);
        }

        if (!std::equal(issuer_id.begin(), issuer_id.end(), pan.begin())) {
            pr_debug("issuer id ", issuer_id, " not equal to pan ", pan, "\n");
            return false;
        }

        auto& today = db[TRANSACTION_DATE_9A];
        std::vector<uint8_t> date{recovered.cbegin() + 6, recovered.cbegin() + 8}; // MMYY
        if (date[1] < today[0] || (date[1] == today[0] && date[0] < today[1])) {
            pr_debug("issuer certificate date ", date, " expired, today ", today, "\n");
            return false;
        }

        if (on_revocation_list(cak, std::vector<uint8_t>{recovered.cbegin() + 8,
                                                         recovered.cbegin() + 11})) {
            pr_debug("certificate on revocation list\n");
            return false;
        }

        if (recovered[11] != 0x01 || recovered[12] != 0x01) {
            pr_debug("public key or hash algorithm not correct\n");
            return false;
        }

        issuer_modulus.swap(pubkey);
        return true;
    };

    bool on_revocation_list(const cakey* cak, const std::vector<uint8_t>& serial) {
        return false;
    };

private:
    void clear_candidates() {
        candidates.clear();
        state_wait_for_select_aid.last_choice = candidates.begin();
    };

    void enter_express_mode(std::vector<uint8_t> const& apdu) {
        clear_candidates();
        uint8_t sw1 = apdu[apdu.size() - 2];
        uint8_t sw2 = apdu[apdu.size() - 1];
        if (sw1 == 0x90 && sw2 == 0x00) {
            tlv_db fci{};
            auto parser = [&fci](uint32_t tag, auto begin, auto end, bool constructed) mutable -> bool {
                if (!constructed) {
                    std::vector<uint8_t> v{begin, end};
                    fci.emplace(tag, std::move(v));
                };
                return true;
            };
            tlv_visit(apdu.begin(), apdu.end() - 2, parser);

            // rebuild the candidate list with only one matching
            // what is already selected
            auto& df_name = fci[DF_NAME_84];
            pr_debug("express mode for ", df_name, "\n");
            for (auto& combo : combinations) {
                if (combo.aid == df_name) {
                    active_kernel_tag_set = (combo.kid == KERNEL_ID::KERNEL_2) ? &KERNEL2_NS::all_tags_set : &KERNEL3_NS::all_tags_set;
                    candidate c{};
                    c.adf_name = df_name;
                    c.combo = &combo;
                    candidates.push_back(c);
                    state_wait_for_select_aid.last_choice = candidates.begin();
                    // now we are ready to start kernel
                    set_state(&state_wait_for_select_aid);
                    l2_state->handle_apdu(apdu);
                    return;
                }
            }
        };

        // this will lead to error handling, since candidates number is ZERO
        select_combination();
    };

    void start_combination_selection() {
        // 3.3.2.1
        if (whence == RESTART_POINT::B) {
            pr_debug("restart from B!!!\n");
            if (issuer_script_avail) {
                pr_debug("issuer scripts available!!!\n");
                // goto 3.3.3.3
                select_candidate(state_wait_for_select_aid.last_choice);
                return;
            }
            // else goto STEP 1 - 3
        } else if (whence == RESTART_POINT::C) {
            // goto step 3
            select_combination();
            return;
        }

        // STEP 1 3.3.2.2
        std::string ppse = "2PAY.SYS.DDF01";
        std::vector<uint8_t> data(ppse.size());
        for (unsigned i = 0; i != data.size(); i++)
            data[i] = ppse[i];
        send_apdu(apdu_builder::build(COMMANDS::SELECT).data(data).le(0).to_bytes());
        set_state(&state_wait_for_ppse);
    };

    void protocol_activation(bool restart_flag) {
        // 3.2.1.1
        if (!restart_flag) {
            if (whence == RESTART_POINT::B) {
                for (auto& combo : combinations) {
                    const transaction_cfg* cfg = combo.transact;
                    combo.indicator = preprocessing_indicator{};
                    preprocessing_indicator& indicator = combo.indicator;

                    // 3.1.1.2
                    if (cfg->db.has_tag(TTQ_9F66)) {
                        indicator.ttq = cfg->db[TTQ_9F66];
                    }
                }
            }

            clear_candidates();
        }

        // 3.2.1.2
        if (restart_flag && retained_restart_ui_present) {
            send_ui_event(retained_restart_ui);
        } else {
            // otherwise ask user to present card
            ui_req_data ui;
            ui.ui_id = ui_message_id::PRESENT_CARD;
            ui.status = ui_status_id::PRESENT_CARD;
            send_ui_event(ui);
        }

        // 3.2.1.3
        message out{MESSAGE_ID::L1_POWER_UP, EMV_MODULE::L2, EMV_MODULE::L1};
        out.send();
    };

    void start_transaction(const tlv_db& transaction_req) {
        if (transaction_req.has_tag(AMOUNT_AUTHORISED_9F02)) {
            whence = RESTART_POINT::A;
            pr_debug("START TRASANCTION -> A\n");
            preprocessing(transaction_req);
        } else {
            pr_debug("START TRANSACTION -> B\n");
            whence = RESTART_POINT::B;
            protocol_activation(false);
        }
    };

    bool preprocessing(const tlv_db& transaction_req) {
        bool contactless_not_allowed = true;
        combinations = std::vector<combination>{};
        auto transact_type = narrow_cast<TRANSACTION_TYPE>(transaction_req.get_numeric_value(TRANSACTION_TYPE_9C));

        pr_debug("look for comb with transaction type ", static_cast<int>(transact_type), "\n");
        for (unsigned i = 0; i != l2_cfgs.kernel_cfgs.size(); i++) {
            const kernel_cfg* krn = &l2_cfgs.kernel_cfgs[i];
            for (unsigned j = 0; j != krn->app_cfgs.size(); j++) {
                const application_cfg* app = &krn->app_cfgs[j];
                for (unsigned k = 0; k != app->tr_cfgs.size(); k++) {
                    const transaction_cfg* tr = &app->tr_cfgs[k];
                    if (tr->transact_type == transact_type) {
                        pr_debug("select combination : ", (int)krn->kid, " : ", app->aid, "\n");
                        combination combo{krn->kid, app->aid};
                        combo.krn = krn;
                        combo.app = app;
                        combo.transact = tr;
                        combinations.push_back(combo);
                    }
                }
            }
        };

        for (auto& combo : combinations) {
            combo.db.insert(transaction_req);
            combination_preprocessing(combo, transact_type);
            if (!combo.indicator.contactless_not_allowed) {
                contactless_not_allowed = false;
            }
        }

        // 3.1.1.13
        if (contactless_not_allowed) {
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
            generate_outcome(o);
            return false;
        }

        protocol_activation(false);
        return true;
    };

    void combination_preprocessing(combination& combo, TRANSACTION_TYPE transact_type) {
        pr_debug("preprocessing combo, kernel ", static_cast<int>(combo.kid), " aid ", combo.aid, "\n");
        const transaction_cfg* cfg = combo.transact;
        preprocessing_indicator& indicator = combo.indicator;

        // 3.1.1.2
        if (cfg->db.has_tag(TTQ_9F66)) {
            indicator.ttq = cfg->db[TTQ_9F66];
        }

        if (indicator.ttq) {
            auto& p = *(indicator.ttq);
            v_clear_bit(p, TTQ_9F66.online_cryptogram_required);
            v_clear_bit(p, TTQ_9F66.cvm_required);
        }

        // 3.1.1.3
        auto amount = combo.db.get_numeric_value(AMOUNT_AUTHORISED_9F02);
        if (cfg->status_check_support &&
            cfg->status_check_support.value() &&
            AMOUNT_AUTHORISED_9F02.is_single_unit_currency(amount)) {
            pr_debug("single unit currency ", combo.db[AMOUNT_AUTHORISED_9F02], " -> ", (int)amount, "\n");
            indicator.status_check_requested = true;
        }

        // 3.1.1.4
        if (amount == 0) {
            if (cfg->zero_amount_allowed &&
                !cfg->zero_amount_allowed.value()) {
                pr_debug("zero amount == 0, is not allowed\n");
                indicator.contactless_not_allowed = true;
            } else {
                indicator.zero_amount = true;
            }
        }

        // 3.1.1.5
        if (cfg->reader_contactless_transaction_limit &&
            amount >= cfg->reader_contactless_transaction_limit.value()) {
            pr_debug("amount ", (int)amount, " > limit ", (int)cfg->reader_contactless_transaction_limit.value(), "  not allowed\n");
            indicator.contactless_not_allowed = true;
        }

        // 3.1.1.6
        if (cfg->reader_contactless_floor_limit &&
            amount >= cfg->reader_contactless_floor_limit.value()) {
            pr_debug("amount ", (int)amount, " > ", "limit ", (int)cfg->reader_contactless_floor_limit.value(), "\n");
            indicator.reader_contactless_floor_limit_exeeded = true;
        }

        // 3.1.1.7
        if (!(cfg->reader_contactless_floor_limit) &&
            cfg->terminal_floor_limit_9F1B &&
            amount >= cfg->terminal_floor_limit_9F1B.value()) {
            indicator.reader_contactless_floor_limit_exeeded = true;
        }

        // 3.1.1.8
        if (cfg->reader_cvm_required_limit &&
            amount >= cfg->reader_cvm_required_limit.value()) {
            indicator.reader_cvm_required_limit_exceeded = true;
        }

        if (indicator.ttq) {
            auto& p = *(indicator.ttq);

            // 3.1.1.9
            if (indicator.reader_contactless_floor_limit_exeeded) {
                pr_debug("floor limit exeeded, go online\n");
                v_set_bit(p, TTQ_9F66.online_cryptogram_required);
            }
            // 3.1.1.10
            if (indicator.status_check_requested) {
                pr_debug("status check requested, go online\n");
                v_set_bit(p, TTQ_9F66.online_cryptogram_required);
            }

            //3.1.1.11
            if (indicator.zero_amount) {
                if (!v_get_bit(p, TTQ_9F66.offline_only_reader)) {
                    pr_debug("zero amount, go online\n");
                    v_set_bit(p, TTQ_9F66.online_cryptogram_required);
                } else {
                    indicator.contactless_not_allowed = true;
                }
            }

            //3.1.1.12
            if (indicator.reader_cvm_required_limit_exceeded) {
                v_set_bit(p, TTQ_9F66.cvm_required);
            }
        }
    }

    void select_kernel(uint8_t sw1, uint8_t sw2, const tlv_db& fci) {
        auto choice = state_wait_for_select_aid.last_choice;

        if (sw1 != 0x90 || sw2 != 0x00) {
            pr_debug("select of aid failed\n");
            // 3.3.3.5
            if (issuer_script_avail) {
                outcome o(OUTCOME_TYPE::END_APPLICATION);
                o.start = RESTART_POINT::NA;
                o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
                o.cvm = OUTCOME_CVM::NA;
                o.ui_request = true;
                o.ui_request_data.ui_id = ui_message_id::INSERT_SWIPE_TRY_ANOTHER;
                o.ui_request_data.status = ui_status_id::PRESENT_CARD;
                o.ui_on_restart = false;
                o.data_record_present = false;
                o.discretionary_data_present = false;
                o.alt_interface = INTERFACE_TYPE::NA;
                o.receipt = false;
                o.field_off_request = -1;
                o.removal_timeout = 0;
                generate_outcome(o);
                return;
            } else {
                // remove current combination
                candidates.erase(state_wait_for_select_aid.last_choice);
                state_wait_for_select_aid.last_choice = candidates.begin(); // last_choice was invalidated
                // goto 3.3.2.6 STEP 3
                select_combination();
            }
        } else {
            // 3.3.3.6
            std::vector<uint8_t> df_name;
            if (fci.has_tag(DF_NAME_84))
                df_name = fci[DF_NAME_84];

            std::vector<dol_elem> pdol{};
            if (fci.has_tag(PDOL_9F38)) {
                auto& v = fci[PDOL_9F38];
                tlv_parse_dol(v.begin(), v.end(), pdol);
            };

            for (auto& p : pdol) {
                pr_debug("PDOL ", to_hex(p.tag), " len ", static_cast<int>(p.length), "\n");
            };

            if (std::equal(VISA_AID.begin(), VISA_AID.end(), df_name.begin()) &&
                (choice->combo->kid == KERNEL_ID::KERNEL_3) &&
                (pdol.size() == 0 || std::find_if(pdol.begin(), pdol.end(), [](auto& p) { return p.tag == TTQ_9F66.id; }) == pdol.end())) {
                logger.info("no pdol or no TTQ 9F66 in pdol\n");
                candidates.erase(state_wait_for_select_aid.last_choice);
                state_wait_for_select_aid.last_choice = candidates.begin(); // last choice was invalidated
                select_combination();
            } else {
                activate_kernel(sw1, sw2, fci, *state_wait_for_select_aid.last_choice);
            }
        }
    };

    void activate_kernel(uint8_t sw1, uint8_t sw2, const tlv_db& fci, candidate& candy) {
        set_state(&state_default);
        kernel* k = emv_kernel_factory->get_kernel((candy.combo)->kid);
        k->start(sw1, sw1, fci, &candy, issuer_script_avail ? issuer_update_scripts : issuer_script{}, this);
    };

    void prepare_candidates(uint8_t sw1, uint8_t sw2, const std::vector<tlv_db>& apps) {
        candidates.clear();
        if ((sw1 == 0x90 && sw2 == 0x00) && // 3.3.2.3
            apps.size() > 0) {              // 3.3.2.4
            for (auto& combo : combinations) {
                if (combo.indicator.contactless_not_allowed) {
                    continue;
                }

                for (unsigned order = 0; order != apps.size(); order++) {
                    const tlv_db& app = apps[order];

                    // A
                    if (!app.has_tag(ADF_NAME_4F))
                        continue;
                    auto& adf_name = app[ADF_NAME_4F];
                    if (!ADF_NAME_4F.validate(adf_name))
                        continue;

                    // B
                    if (!std::equal(combo.aid.begin(), combo.aid.end(), adf_name.begin()))
                        continue;

                    // C, D
                    if (app.has_tag(KERNEL_IDENTIFIER_9F2A)) {
                        auto& v = app[KERNEL_IDENTIFIER_9F2A];
                        uint32_t identifier;
                        if (KERNEL_IDENTIFIER_9F2A.get_kid(v, identifier)) {
                            if (identifier != 0 && identifier != static_cast<uint32_t>(combo.kid)) {
                                continue;
                            }
                        }
                    }

                    candidate c{};
                    c.adf_name = adf_name;
                    c.order = order;
                    c.combo = &combo;

                    if (app.has_tag(APPLICATION_PRIORITY_INDICATOR_87)) {
                        c.priority = app(APPLICATION_PRIORITY_INDICATOR_87);
                    };

                    if (app.has_tag(EXTENDED_SELECTION_9F29)) {
                        c.extended_selection = app[EXTENDED_SELECTION_9F29];
                    };

                    pr_debug("candidate ADF : ", c.adf_name, " AID ", combo.aid, " priority : ", c.priority, " order ", order, "\n");
                    candidates.push_back(c);
                }
            }
        }

        // STEP 3
        select_combination();
    }

    void select_combination() {
        // 3.3.2.7
        if (candidates.size() == 0) {
            pr_debug("there is no candidates available\n");
            outcome o(OUTCOME_TYPE::END_APPLICATION);
            o.start = RESTART_POINT::NA;
            o.kernel_restart_cond = OUTCOME_KERNEL_RESTART_COND::NA;
            o.cvm = OUTCOME_CVM::NA;
            o.ui_request = true;
            o.ui_request_data.ui_id = ui_message_id::INSERT_SWIPE_TRY_ANOTHER;
            o.ui_request_data.status = ui_status_id::PRESENT_CARD;
            o.ui_on_restart = false;
            o.data_record_present = false;
            o.discretionary_data_present = false;
            o.alt_interface = INTERFACE_TYPE::NA;
            o.receipt = false;
            o.field_off_request = -1;
            o.removal_timeout = 0;
            generate_outcome(o);
            return;
        }

        // 3.3.2.6
        // final selection 3.3.3
        std::list<candidate>::iterator choice = candidates.begin(); // 3.3.3.1
        if (candidates.size() > 1) { // 3.3.3.2
            for (auto p = std::next(choice); p != candidates.end(); ++p) {
                if (p->priority == 0) {
                    p->priority = 15;
                }
                if (p->priority == choice->priority) {
                    if (p->order < choice->order) {
                        choice = p;
                    }
                } else if (p->priority < choice->priority) {
                    choice = p;
                }
            }
        }

        select_candidate(choice);
    }

    void select_candidate(std::list<candidate>::iterator choice) {
        state_wait_for_select_aid.last_choice = choice;

        //3.3.3.3
        std::vector<uint8_t> aid;
        const transaction_cfg* config = choice->combo->transact;
        if (choice->extended_selection.size() != 0 &&
            config->extended_selection_support &&
            config->extended_selection_support.value()) {
            aid = choice->adf_name;
            const std::vector<uint8_t>& extended_selection = choice->extended_selection;
            pr_debug("append extended select ", choice->extended_selection, " to ", aid, "\n");
            std::copy(extended_selection.begin(), extended_selection.end(), back_inserter(aid));
        } else {
            aid = choice->adf_name;
        }

        pr_debug("select AID : ", aid, "\n");
        send_apdu(apdu_builder::build(COMMANDS::SELECT).data(aid).le(0).to_bytes());
        set_state(&state_wait_for_select_aid);
    }

private:
    bool retained_restart_ui_present;
    bool issuer_script_avail;
    OUTCOME_KERNEL_RESTART_COND retained_condition;
    ui_req_data retained_restart_ui;
    issuer_script issuer_update_scripts;

public:
    const reader_cfg& l2_cfgs;

    // TODO initialize this torn transactions from somewhere
    torn_records torn_transactions;

public:
    std::vector<combination> combinations;
    default_responder state_default;
    ppse_responder state_wait_for_ppse;
    responder* l2_state;
    select_aid_responder state_wait_for_select_aid;
    RESTART_POINT whence;
    std::list<candidate> candidates;
    std::unique_ptr<timer> field_off_timer;
};
}; // namespace contactless

    } // namespace emv

#endif

