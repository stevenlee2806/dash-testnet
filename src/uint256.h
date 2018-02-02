// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include <assert.h>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>
#include "crypto/common.h"


// class uint_error : public std::runtime_error
// {
// public:
//     explicit uint_error(const std::string& str) : std::runtime_error(str) {}
// };

/** Template base class for fixed-sized opaque blobs. */
template<unsigned int BITS>
class base_blob
{
protected:
    enum { WIDTH=BITS/8 };
    uint8_t data[WIDTH];
public:
    base_blob()
    {
        memset(data, 0, sizeof(data));
    }

   

    base_blob(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            data[i] = b.data[i];
    }


    explicit base_blob(const std::string& str);   
    explicit base_blob(const std::vector<unsigned char>& vch);

    base_blob& operator=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            data[i] = b.data[i];
        return *this;
    }


    base_blob(uint64_t b)
    {
        data[0] = (unsigned int)b;
        data[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            data[i] = 0;
    }

     bool operator!() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    const base_blob operator~() const
    {
        base_blob ret;
        for (int i = 0; i < WIDTH; i++)
            ret.data[i] = ~data[i];
        return ret;
    }

    const base_blob operator-() const
    {
        base_blob ret;
        for (int i = 0; i < WIDTH; i++)
            ret.data[i] = ~data[i];
        ret++;
        return ret;
    }

    double getdouble() const;

    base_blob& operator=(uint64_t b)
    {
        data[0] = (unsigned int)b;
        data[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            data[i] = 0;
        return *this;
    }

    base_blob& operator^=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            data[i] ^= b.data[i];
        return *this;
    }

    base_blob& operator&=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            data[i] &= b.data[i];
        return *this;
    }

    base_blob& operator|=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            data[i] |= b.data[i];
        return *this;
    }

    base_blob& operator^=(uint64_t b)
    {
        data[0] ^= (unsigned int)b;
        data[1] ^= (unsigned int)(b >> 32);
        return *this;
    }

    base_blob& operator|=(uint64_t b)
    {
        data[0] |= (unsigned int)b;
        data[1] |= (unsigned int)(b >> 32);
        return *this;
    }

    base_blob& operator<<=(unsigned int shift);
    base_blob& operator>>=(unsigned int shift);

    base_blob& operator+=(const base_blob& b)
    {
        uint64_t carry = 0;
        for (int i = 0; i < WIDTH; i++) {
            uint64_t n = carry + data[i] + b.data[i];
            data[i] = n & 0xffffffff;
            carry = n >> 32;
        }
        return *this;
    }

    base_blob& operator-=(const base_blob& b)
    {
        *this += -b;
        return *this;
    }

    base_blob& operator+=(uint64_t b64)
    {
        base_blob b;
        b = b64;
        *this += b;
        return *this;
    }

    base_blob& operator-=(uint64_t b64)
    {
        base_blob b;
        b = b64;
        *this += -b;
        return *this;
    }

    base_blob& operator*=(uint32_t b32);
    base_blob& operator*=(const base_blob& b);
    base_blob& operator/=(const base_blob& b);

    base_blob& operator++()
    {
        // prefix operator
        int i = 0;
        while (++data[i] == 0 && i < WIDTH - 1)
            i++;
        return *this;
    }

    const base_blob operator++(int)
    {
        // postfix operator
        const base_blob ret = *this;
        ++(*this);
        return ret;
    }

    base_blob& operator--()
    {
        // prefix operator
        int i = 0;
        while (--data[i] == (uint32_t)-1 && i < WIDTH - 1)
            i++;
        return *this;
    }

    const base_blob operator--(int)
    {
        // postfix operator
        const base_blob ret = *this;
        --(*this);
        return ret;
    }

    int CompareTo(const base_blob& b) const;
    bool EqualTo(uint64_t b) const;

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(data, 0, sizeof(data));
    }


    friend inline const base_blob operator+(const base_blob& a, const base_blob& b) { return base_blob(a) += b; }
    friend inline const base_blob operator-(const base_blob& a, const base_blob& b) { return base_blob(a) -= b; }
    friend inline const base_blob operator*(const base_blob& a, const base_blob& b) { return base_blob(a) *= b; }
    friend inline const base_blob operator/(const base_blob& a, const base_blob& b) { return base_blob(a) /= b; }
    friend inline const base_blob operator|(const base_blob& a, const base_blob& b) { return base_blob(a) |= b; }
    friend inline const base_blob operator&(const base_blob& a, const base_blob& b) { return base_blob(a) &= b; }
    friend inline const base_blob operator^(const base_blob& a, const base_blob& b) { return base_blob(a) ^= b; }
    friend inline const base_blob operator>>(const base_blob& a, int shift) { return base_blob(a) >>= shift; }
    friend inline const base_blob operator<<(const base_blob& a, int shift) { return base_blob(a) <<= shift; }
    friend inline const base_blob operator*(const base_blob& a, uint32_t b) { return base_blob(a) *= b; }
    friend inline bool operator==(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) == 0; }
    friend inline bool operator!=(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) != 0; }
    friend inline bool operator>(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) > 0; }
    friend inline bool operator<(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) < 0; }
    friend inline bool operator>=(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) >= 0; }
    friend inline bool operator<=(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) <= 0; }
    // friend inline bool operator>(const base_blob& a, const base_blob& b) { return a.CompareTo(b) > 0; }
    // friend inline bool operator<(const base_blob& a, const base_blob& b) { return a.CompareTo(b) < 0; }
    // friend inline bool operator>=(const base_blob& a, const base_blob& b) { return a.CompareTo(b) >= 0; }
    // friend inline bool operator<=(const base_blob& a, const base_blob& b) { return a.CompareTo(b) <= 0; }
    // friend inline bool operator==(const base_blob& a, uint64_t b) { return a.EqualTo(b); }
    // friend inline bool operator!=(const base_blob& a, uint64_t b) { return !a.EqualTo(b); }

    // friend inline bool operator==(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) == 0; }
    // friend inline bool operator!=(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) != 0; }
    // friend inline bool operator<(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) < 0; }

    std::string GetHex() const;
    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    std::string ToString() const;

     /**
     * Returns the position of the highest bit set plus one, or zero if the
     * value is zero.
     */
    unsigned int bits() const;

    unsigned char* begin()
    {
        return &data[0];
    }

    unsigned char* end()
    {
        return &data[WIDTH];
    }

    const unsigned char* begin() const
    {
        return &data[0];
    }

    const unsigned char* end() const
    {
        return &data[WIDTH];
    }

    unsigned int size() const
    {
        return sizeof(data);
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return sizeof(data);
    }

    uint64_t GetUint64(int pos) const
    {
        const uint8_t* ptr = data + pos * 8;
        return ((uint64_t)ptr[0]) | \
               ((uint64_t)ptr[1]) << 8 | \
               ((uint64_t)ptr[2]) << 16 | \
               ((uint64_t)ptr[3]) << 24 | \
               ((uint64_t)ptr[4]) << 32 | \
               ((uint64_t)ptr[5]) << 40 | \
               ((uint64_t)ptr[6]) << 48 | \
               ((uint64_t)ptr[7]) << 56;
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        s.write((char*)data, sizeof(data));
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        s.read((char*)data, sizeof(data));
    }

    friend class uint160;
    friend class uint256;    
    friend class uint512;
};

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    uint160() {}
    uint160(const base_blob<160>& b) : base_blob<160>(b) {}
    explicit uint160(const std::vector<unsigned char>& vch) : base_blob<160>(vch) {}
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    uint256() {}
    uint256(const base_blob<256>& b) : base_blob<256>(b) {}
    explicit uint256(const std::vector<unsigned char>& vch) : base_blob<256>(vch) {}

    /** A cheap hash function that just returns 64 bits from the result, it can be
     * used when the contents are considered uniformly random. It is not appropriate
     * when the value can easily be influenced from outside as e.g. a network adversary could
     * provide values to trigger worst-case behavior.
     */
    uint64_t GetCheapHash() const
    {
        return ReadLE64(data);
    }
};

/* uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can result
 * in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char *str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}
/* uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string &str) can result
 * in dangerously catching uint256(0) via std::string(const char*).
 */
inline uint256 uint256S(const std::string& str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}

// /** 512-bit unsigned big integer. */
// class uint512 : public base_blob<512> {
// public:
//     uint512() {}
//     uint512(const base_blob<512>& b) : base_blob<512>(b) {}
//     explicit uint512(const std::vector<unsigned char>& vch) : base_blob<512>(vch) {}

//     uint256 trim256() const
//     {
//         uint256 result;
//         memcpy((void*)&result, (void*)data, 32);
//         return result;
//     }
//     uint64_t GetCheapHash() const
//     {
//         return ReadLE64(data);
//     }
// };

// /* uint256 from const char *.
//  * This is a separate function because the constructor uint256(const char*) can result
//  * in dangerously catching uint256(0).
//  */
// inline uint512 uint512S(const char* str)
// {
//     uint512 rv;
//     rv.SetHex(str);
//     return rv;
// }



/** 512-bit unsigned big integer. */
class uint512 : public base_blob<512>
{
public:
    uint512() {}
    uint512(const base_blob<512>& b) : base_blob<512>(b) {}
    uint512(uint64_t b) : base_blob<512>(b) {}
    explicit uint512(const std::string& str) : base_blob<512>(str) {}
    explicit uint512(const std::vector<unsigned char>& vch) : base_blob<512>(vch) {}

    uint256 trim256() const
    {
        uint256 ret;
        for (unsigned int i = 0; i < uint256::WIDTH; i++) {
            ret.data[i] =data[i];
        }
        return ret;
    }
};

inline uint512 uint512S(const std::string& str)
{
    uint512 rv;
    rv.SetHex(str);
    return rv;
}


#endif // BITCOIN_UINT256_H
