#!/usr/bin/env python3

# Copyright (c) 2023 Julian Parkin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Generates regexes for RFC7452-compliant NAIs

if __name__ == '__main__':
    utf8_atex     =  '[a-zA-Z0-9!#$%&\'\\\\*\\\\+\\\\-/=\\\\?\\\\^_`{\\\\|}~\\\\x{80}-\\\\x{10FFFF}]'

    string_       = f'(?:{utf8_atex})+'
    dot_string    = f'{string_}(?:\\\\.{string_})*'
    utf8_username = dot_string

    utf8_rtext    =  '[a-zA-Z0-9\\\\x{80}-\\\\x{10FFFF}]'
    ldh_str       = f'(?:{utf8_rtext}|-)*{utf8_rtext}'
    label         = f'{utf8_rtext}(?:{ldh_str})*'

    utf8_realm    = f'(?:{label}\\\\.)+{label}'

    nai           = f'(?<usernameOnly>{utf8_username})'
    nai          += f'|@(?<realmOnly>{utf8_realm})'
    nai          += f'|(?<username>{utf8_username})@(?<realm>{utf8_realm})'

    print(nai)
    print(utf8_username)
    print(utf8_realm)
