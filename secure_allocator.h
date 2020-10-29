#ifndef SECURE_ALLOC_H
#define SECURE_ALLOC_H

#include <cstring>
#include <memory>
#include <string>
#include <vector>

// for now the only purpose of secure allocator is to clear senstive data
// from memory during deallocation in a hostile environment
//
// It is not necessary for a tamper-proof environment
// so define or undef USE_SECURE_ALLOCATOR to suit your own need
//
// Perhaps in the future we can migrate whole code into a custom allocator, which
// can be essential for some embedded system to build
//
#ifdef USE_SECURE_ALLOCATOR

template <typename T>
class default_secure_allocator : public std::allocator<T>
{
public:
    typedef size_t size_type;
    typedef T* pointer;
    typedef const T* const_pointer;

    template <typename U>
    struct rebind {
        typedef default_secure_allocator<U> other;
    };

    pointer allocate(size_type n, const void* hint = 0)
    {
        return std::allocator<T>::allocate(n, hint);
    }

    void deallocate(pointer p, size_type n)
    {
        std::memset(p, 0, n * sizeof(T));
        return std::allocator<T>::deallocate(p, n);
    }

    default_secure_allocator() throw() : std::allocator<T>(){};
    default_secure_allocator(const default_secure_allocator& a) throw() : std::allocator<T>(a) {}
    template <typename U>
    default_secure_allocator(const default_secure_allocator<U>& a) throw() : std::allocator<T>(a) {}
    ~default_secure_allocator() throw() {}
};

using secure_vector = std::vector<uint8_t, default_secure_allocator<uint8_t>>;
using secure_string = std::basic_string<char, std::char_traits<char>, default_secure_allocator<char>>;

namespace std
{
template <>
struct hash<secure_string> {
    size_t operator()(const secure_string& k) const
    {
        std::string s(k.begin(), k.end());
        auto h = std::hash<std::string>{}(s);
        for (auto& x : s) // erase the unsecure copy
            x = 0;
        return h;
    }
};
}; // namespace std

#else

using secure_vector = std::vector<uint8_t>;
using secure_string = std::string;

#endif

#endif
