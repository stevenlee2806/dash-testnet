// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uint256.h"

#include "utilstrencodings.h"

#include <stdio.h>
#include <string.h>



template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::string& str)
{
    SetHex(str);
}

// template <unsigned int BITS>
// base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
// {
//     if (vch.size() != sizeof(data))
//         throw uint_error("Converting vector of wrong size to base_blob");
//     memcpy(data, &vch[0], sizeof(data));
// }

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
{
    assert(vch.size() == sizeof(data));
    memcpy(data, &vch[0], sizeof(data));
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator<<=(unsigned int shift)
{
    base_blob<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        data[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i + k + 1 < WIDTH && shift != 0)
            data[i + k + 1] |= (a.data[i] >> (32 - shift));
        if (i + k < WIDTH)
            data[i + k] |= (a.data[i] << shift);
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator>>=(unsigned int shift)
{
    base_blob<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        data[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            data[i - k - 1] |= (a.data[i] << (32 - shift));
        if (i - k >= 0)
            data[i - k] |= (a.data[i] >> shift);
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator*=(uint32_t b32)
{
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; i++) {
        uint64_t n = carry + (uint64_t)b32 * data[i];
        data[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator*=(const base_blob& b)
{
    base_blob<BITS> a = *this;
    *this = 0;
    for (int j = 0; j < WIDTH; j++) {
        uint64_t carry = 0;
        for (int i = 0; i + j < WIDTH; i++) {
            uint64_t n = carry + data[i + j] + (uint64_t)a.data[j] * b.data[i];
            data[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    return *this;
}

template <unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator/=(const base_blob& b)
{
    base_blob<BITS> div = b;     // make a copy, so we can shift.
    base_blob<BITS> num = *this; // make a copy, so we can subtract.
    *this = 0;                   // the quotient.
    int num_bits = num.bits();
    int div_bits = div.bits();
    if (div_bits == 0)
         throw std::runtime_error("Division by zero");
    if (div_bits > num_bits) // the result is certainly 0.
        return *this;
    int shift = num_bits - div_bits;
    div <<= shift; // shift so that div and nun align.
    while (shift >= 0) {
        if (num >= div) {
            num -= div;
            data[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        div >>= 1; // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return *this;
}


template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    char psz[sizeof(data) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(data); i++)
        sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
    return std::string(psz, psz + sizeof(data) * 2);
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const char* psz)
{
    memset(data, 0, sizeof(data));

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (::HexDigit(*psz) != -1)
        psz++;
    psz--;
    unsigned char* p1 = (unsigned char*)data;
    unsigned char* pend = p1 + WIDTH;
    while (psz >= pbegin && p1 < pend) {
        *p1 = ::HexDigit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)::HexDigit(*psz--) << 4);
            p1++;
        }
    }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const
{
    return (GetHex());
}

template <unsigned int BITS>
unsigned int base_blob<BITS>::bits() const
{
    for (int pos = WIDTH - 1; pos >= 0; pos--) {
        if (data[pos]) {
            for (int bits = 31; bits > 0; bits--) {
                if (data[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}


template <unsigned int BITS>
int base_blob<BITS>::CompareTo(const base_blob<BITS>& b) const
{
    for (int i = WIDTH - 1; i >= 0; i--) {
        if (data[i] < b.data[i])
            return -1;
        if (data[i] > b.data[i])
            return 1;
    }
    return 0;
}

template <unsigned int BITS>
bool base_blob<BITS>::EqualTo(uint64_t b) const
{
    for (int i = WIDTH - 1; i >= 2; i--) {
        if (data[i])
            return false;
    }
    if (data[1] != (b >> 32))
        return false;
    if (data[0] != (b & 0xfffffffful))
        return false;
    return true;
}

// Explicit instantiations for base_blob<160>
template base_blob<160>::base_blob(const std::vector<unsigned char>&);
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;
template void base_blob<160>::SetHex(const char*);
template void base_blob<160>::SetHex(const std::string&);
template int base_blob<160>::CompareTo(const base_blob<160>&) const;
template bool base_blob<160>::EqualTo(uint64_t) const;


// Explicit instantiations for base_blob<256>
template base_blob<256>::base_blob(const std::vector<unsigned char>&);
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;
template void base_blob<256>::SetHex(const char*);
template void base_blob<256>::SetHex(const std::string&);
template int base_blob<256>::CompareTo(const base_blob<256>&) const;
template bool base_blob<256>::EqualTo(uint64_t) const;

// Explicit instantiations for base_blob<512>
template base_blob<512>::base_blob(const std::string&);
template base_blob<512>& base_blob<512>::operator<<=(unsigned int);
template base_blob<512>& base_blob<512>::operator>>=(unsigned int);
template std::string base_blob<512>::GetHex() const;
template std::string base_blob<512>::ToString() const;
// template std::string base_blob<512>::ToStringReverseEndian() const;
