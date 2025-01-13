// Copyright (c) 2024 Julian Parkin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdio.h>

#define LEN(x) (sizeof(x) / sizeof(x[0]))

// Definitions from milenage.c

typedef unsigned char u8;

extern u8 OP[16];

void f1(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_a[8]);
void f2345(u8 k[16], u8 rand[16], u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6]);
void f1star(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_s[8]);
void f5star(u8 k[16], u8 rand[16], u8 ak[6]);

void print_arr(char *name, u8 arr[], int len)
{
    printf("%s = hex.parseHex(\"", name);
    for (int i = 0; i < len; i++)
        printf("%02x", arr[i]);
    printf("\");\n");
}

int main(int argc, char **argv)
{
    u8 k[]    = { 0xDC, 0xFF, 0xED, 0x9B, 0x05, 0xEE, 0x5A, 0xA9,
                  0xC2, 0xAD, 0x02, 0xBF, 0x9C, 0xD1, 0x8D, 0x46 };
    u8 rand[] = { 0x93, 0xC3, 0xD1, 0x8F, 0x12, 0x2E, 0xA4, 0x76,
                  0xF4, 0x4D, 0x60, 0xD5, 0x3D, 0x40, 0xD1, 0xD1 };
    u8 sqn[]  = { 0x6E, 0xD9, 0x0F, 0x35, 0x6F, 0xD9 };
    u8 amf[]  = { 0x0F, 0x7A };

    u8 f1_res      [ 8];
    u8 f1_star_res [ 8];
    u8 f2_res      [ 8];
    u8 f3_res      [16];
    u8 f4_res      [16];
    u8 f5_res      [ 6];
    u8 f5_star_res [ 6];

    f1     (k, rand, sqn, amf, f1_res);
    f1star (k, rand, sqn, amf, f1_star_res);
    f2345  (k, rand, f2_res, f3_res, f4_res, f5_res);
    f5star (k, rand, f5_star_res);

    print_arr("op",   OP,   LEN(OP));
    print_arr("k",    k,    LEN(k));
    print_arr("amf",  amf,  LEN(amf));
    print_arr("rand", rand, LEN(rand));
    print_arr("sqn",  sqn,  LEN(sqn));

    print_arr("f1",      f1_res,      LEN(f1_res));
    print_arr("f1_star", f1_star_res, LEN(f1_star_res));
    print_arr("f2",      f2_res,      LEN(f2_res));
    print_arr("f3",      f3_res,      LEN(f3_res));
    print_arr("f4",      f4_res,      LEN(f4_res));
    print_arr("f5",      f5_res,      LEN(f5_res));
    print_arr("f5_star", f5_star_res, LEN(f5_star_res));

    return 0;
}
