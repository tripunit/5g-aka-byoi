// Copyright (c) 2023-2025 Julian Parkin
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

divert(-1)

define(`MAX_HTTP', `2')

define(`m4_for',
    `pushdef(`$1', `$2')_$0($@)popdef(`$1')')

define(`_m4_for',
    `$4`'ifelse($1, `$3', `', `define(`$1', incr($1))$0($@)')')

define(`m4_const',
    changequote([,])[changequote([,])'$1'changequote(`,')]changequote(`,'))

changecom()

define(`USER_SESSION_PID', 1)

divert(0)

theory byoi_stg1

begin

builtins
    : asymmetric-encryption
    , hashing
    , natural-numbers
    , xor
    , signing
    , symmetric-encryption

functions
    : kdf/2
    , f1/2
    , f2/2
    , f3/2
    , f4/2
    , f5/2
    , f1_star/2
    , f5_star/2

// --- Tactics: Sources ---

tactic: source_ue_hn_sqn
presort: C
prio:
    regex "HnSqnUse"
    regex "UeSqnUse"
prio:
    regex "HnSqn"
    regex "UeSqn"

tactic: source_ue_cookie
presort: C
prio:
    regex "\(last\("
prio:
    regex "!KU\( as_params.* \) @ #j"
    regex "!KU\( <.*code_challenge> \) @ #j "
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "BrowserCookie\("

tactic: source_hn_authz_code_ue_as_params_combined
presort: C
prio:
    regex "\(last\("
prio:
    regex "~~>"
prio:
    regex "!KU\( as_params \) @ #j"
prio:
    regex "!KU\( cookie \) @ #j"
    regex "AsCookieSet\("
prio:
    regex "HnState0\("
    regex "UeState0\("
prio:
    regex "SecureRecv\(.*<'auth_res'"
    regex "!KU\( senc\(<authz_code"
    regex "!KU\( senc\(<<protocol"
prio:
    regex "SecureRecv\("

tactic: source_sn_auth_request
presort: C
prio:
    regex "\(last\("
prio:
    regex "~~>"
prio:
    regex "!AsClient\(.*~channel"
prio:
    regex "!KU\( as_params \) @ #j"
    regex "!KU\( authz_code \) @ #j"
    regex "!KU\( cookie \) @ #j"
    regex "AsCookieSet\("
prio:
    regex "SnState0\("
prio:
    regex "SecureRecv\( ~channel"
    regex "!KU\( ~channel"

// --- Tactics: Helpers ---

tactic: helper_browser_request_matching
presort: C
prio:
    regex "BrowserSend\("
    regex "BrowserRecv\("
    regex "BrowserState0\("
prio:
    regex "HttpClientRecv\d\("

tactic: helper_browser_cookie_matching1
presort: C
prio:
    regex "\(last\("
prio:
    regex "~~>"
prio:
    regex "!Browser\("
prio:
    regex "BrowserCookie\("

tactic: helper_browser_cookie_matching2
presort: C
prio:
    regex "\(last\("
prio:
    regex "~~>"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "BrowserState0\("
prio:
    regex "BrowserRecv\("
prio:
    regex "BrowserSend\("
prio:
    regex "BrowserRecv\(.*\) @ #j"

tactic: helper_ue_sqn_ordering
presort: C
prio:
    regex "\(last\("
prio:
    regex "~~>"
prio:
    regex " UeSqn\(.*\).*#i"
    regex " UeSqn\(.*\).*#j"
prio:
    regex "^\s*\(#i"

tactic: helper_ue_sqn_unique
presort: C
prio:
    regex "#i < #j"

tactic: helper_secrecy_oauth_state
presort: C
prio:
    regex "SecureRecv\( ~k"
    regex "SecureRecv\( ~session_cookie"
    regex "SecureRecv\( ~state"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "!KU\( kdf\(<f3\(~k,.*'5GBYOIEKUE'"
    regex "!KU\( kdf\(<f3\(~k,.*'5GBYOIEKHN'"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "!Ue\("
    regex "UeState0\("
prio:
    regex "!KU\( senc\(<<protocol, as"
prio:
    regex "!KU\( ~state \)"
prio:
    regex "BrowserRecv\("
prio:
    regex "!KU\( senc\(<<'HTTPS',.*~state,"
prio:
    regex "!KU\( senc\(<\s*<<'BYOI',.*~state,"
prio:
    regex "SecureRecv\(.*'auth_res',.*~state,"
prio:
    regex "!KU\( ~session_cookie \)"
prio:
    regex ".*\(BrowserSend\("

// --- Tactics: Executability ---

tactic: executability_honest
presort: C
prio:
    regex "~~>"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "!KU\( ~sk"
    regex "!KU\( f5\(~k"
    regex "!KU\( ~base"
prio:
    regex "SnState3\("
prio:
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "SecureRecv\(.*<'auth_req'"
prio:
    regex "SecureRecv\("
prio:
    regex "HnSqn\("
    regex "UeSqn\("
prio:
    regex "!Browser\("
prio:
    regex "^BrowserSend\("
prio:
    regex "BrowserState0\("
prio:
    regex "BrowserRecv\("
prio:
    regex ".*\(BrowserSend\("
prio:
    regex "BrowserState1\("
prio:
    regex "UePossession\("
prio:
    regex "!KU\( kdf\(<f3"
prio:
    regex "!KU\( senc\('security_mode_complete'"
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "!KU\( senc\(<<'HTTPS'"
prio:
    regex "BrowserCookie\("
prio:
    regex "HttpServerSend\d\("
prio:
    regex "!KU\( \(f5\(~k"
    regex "!KD\( \(f5\(~k"
prio:
    regex "!KU\( f1\(~k"
    regex "!KU\( senc\("

// --- Tactics: Secrecy ---

tactic: secrecy_supi
presort: C
prio:
    regex "SecureRecv\( ~ue"
    regex "SecureRecv\( ~sk"
prio:
    regex "!KU\( ~sk"
prio:
    regex "Secret\("
prio:
    regex "!Ue\("
prio:
    regex "SecureRecv\(.*'auth_confirm'"
prio:
    regex "SnState2\("
prio:
    regex "SecureRecv\(.*'auth_req',.*rand"
prio:
    regex "!KU\( ~ue"

tactic: secrecy_supi_sn
presort: C
prio:
    regex "SecureRecv\( ~ue"
    regex "SecureRecv\( ~sk"
prio:
    regex "!KU\( ~sk"
prio:
    regex "Secret\("
prio:
    regex "!Ue\("
prio:
    regex "SecureRecv\(.*'auth_confirm'"
prio:
    regex "SnState2\("
prio:
    regex "SecureRecv\(.*'auth_req',.*rand"
prio:
    regex "!KU\( ~ue"

tactic: secrecy_user_id
presort: C
prio:
    regex "SecureRecv\( ~client_secret"
    regex "SecureRecv\( ~user"
prio:
    regex "!KU\( ~client_secret"
prio:
    regex "Secret\("
prio:
    regex "!User\("
prio:
    regex "!KU\( ~user"

tactic: secrecy_user_id_pkce
presort: C
prio:
    regex "SecureRecv\( ~code_verifier"
    regex "SecureRecv\( ~k"
    regex "SecureRecv\( ~user"
prio:
    regex "BrowserRecv\("
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "!KU\( ~code_verifier"
prio:
    regex "!KU\( kdf\(<f3.*'5GBYOIEKUE'"
    regex "!KU\( kdf\(<f3.*'5GBYOIEKHN'"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Secret\("
prio:
    regex "!User\("
prio:
    regex "!KU\( ~user"
prio:
    regex "!KU\( senc\(<<'HTTPS'.*code_challenge>"
    regex "!KU\( senc\(<<'HTTPS'.*h\(code_verifier\)"
    regex "!KU\( senc\(<<'HTTPS'.*h\(~code_verifier\)"
prio:
    regex "BrowserState0\("

tactic: secrecy_user_password
presort: C
prio:
    regex "SecureRecv\( ~password"
prio:
    regex "Secret\("
prio:
    regex "!User\("
prio:
    regex "!KU\( ~password"

tactic: secrecy_client_secret
presort: C
prio:
    regex "SecureRecv\( ~client_secret"
prio:
    regex "Secret\("
prio:
    regex "!AsClient\("
prio:
    regex "!KU\( ~client_secret"

tactic: secrecy_authz_code
presort: C
prio:
    regex "SecureRecv\( ~authz_code"
    regex "SecureRecv\( ~k"
    regex "SecureRecv\( ~password"
prio:
    regex "!KU\( ~password"
prio:
    regex "!KU\( kdf\(<f3.*'5GBYOIEKHN'"
    regex "!KU\( kdf\(<f3.*'5GBYOIEKUE'"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "Secret\("
prio:
    regex "!User\("
prio:
    regex "HttpServerRecv\d\("
prio:
    regex "!KU\( ~authz_code"
prio:
    regex "!KU\( senc\(<~authz_code"
prio:
    regex "SecureRecv\(.*<'auth_res'.*~authz_code,"
prio:
    regex "!KU\( senc\(<<'HTTPS'.*~client"
prio:
    regex "BrowserState0\("
prio:
    regex "BrowserRecv\( request2,"

tactic: secrecy_access_token
presort: C
prio:
    regex "SecureRecv\( ~access_token"
    regex "SecureRecv\( ~client_secret"
prio:
    regex "!KU\( ~client_secret"
prio:
    regex "Secret\("
prio:
    regex "!AsClient\("
prio:
    regex "HttpServerRecv\d\("
prio:
    regex "AsState1\("
prio:
    regex "!KU\( ~access_token"

tactic: secrecy_access_token_pkce
presort: C
prio:
    regex "SecureRecv\( ~access_token"
    regex "SecureRecv\( ~code_verifier"
    regex "SecureRecv\( ~password"
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( ~code_verifier"
    regex "!KU\( ~password"
prio:
    regex "!KU\( kdf\(<f3.*'5GBYOIEKHN'"
    regex "!KU\( kdf\(<f3.*'5GBYOIEKUE'"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "Secret\("
prio:
    regex "!User\("
prio:
    regex "HttpServerRecv\d\("
prio:
    regex "AsState1\("
prio:
    regex "!KU\( ~access_token"
prio:
    regex "!KU\( senc\(<<'HTTPS'.*h\(code_verifier\)"
prio:
    regex "BrowserSend\("
prio:
    regex "BrowserRecv\("
prio:
    regex ".*\(BrowserSend\("

tactic: secrecy_kseaf
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!Ue\("
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Secret\("
prio:
    regex "HnState1\("
prio:
    regex "SecureRecv\(.*<'auth_confirm'"
prio:
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "SecureRecv\(.*<'auth_req'"

// --- Tactics: Weak Agreement ---

tactic: weakagreement_as_user
presort: C
prio:
    regex "SecureRecv\( ~password"
prio:
    regex "!KU\( ~password"
prio:
    regex "Commit\("
prio:
    regex "!User\("
prio:
    regex "AsState1\("

tactic: helper_weakagreement_user_as1
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(<f3.*'5GBYOIEKUE'"
    regex "!KU\( kdf\(<f3.*'5GBYOIEKHN'"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "HnState1\("
    regex "UeState1\("
prio:
    regex "SecureRecv\(.*<'auth_res'.*authz_code2"
prio:
    regex "!KU\( senc\(<authz_code2"
prio:
    regex "f1\(~k,.*~rand"
prio:
    regex "!KU\( senc\(<<protocol.*hn_as\.1"
    regex "!KU\( senc\(<<protocol.*hn_as\.2"

tactic: helper_weakagreement_user_as2
presort: C
prio:
    regex "SecureRecv\( ~request"
prio:
    regex "HnState1\("
prio:
    regex "HttpClientRecv2\("
prio:
    regex "!KU\( ~request \)"

tactic: weakagreement_user_as
presort: C
prio:
    regex "SecureRecv\( ~k"
    regex "SecureRecv\( ~request"
prio:
    regex "!KU\( kdf\(<f3\(~k, ~rand"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "Rev\( ~ue, <'k', key> \).*Rev\( ~as, 'HTTPS' \)"
prio:
    regex "Commit\("
prio:
    regex "!Ue\("
prio:
    regex "UserState0\("
prio:
    regex "UeConnect\("
prio:
    regex "\(~authz_code = authz_code\.1\)"
    regex "\(~authz_code\.1 = ~authz_code\)"
prio:
    regex "!KU\( senc\(<<'HTTPS', ~as, 'authorize'"
prio:
    regex "!KU\( senc\(<<'HTTPS', ~as.*~state"
prio:
    regex "!KU\( f1\(~k,.*~rand,"
prio:
    regex "^BrowserSend\("
prio:
    regex "BrowserRecv\("
prio:
    regex ".*\(BrowserSend\("
prio:
    regex "BrowserState0\("
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "\(AsSendAccessToken\("
prio:
    regex "AsState1\( ~as"
prio:
    regex "!KU\( kdf\(kdf"
prio:
    regex "!KU\( ~request\.3 \)"
    regex "!KU\( ~request\.4 \)"

tactic: weakagreement_user_hn
presort: C
prio:
    regex "SecureRecv\( ~k"
    regex "SecureRecv\( ~request"
prio:
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "Rev\( ~ue, <'k', key> \).*Rev\( ~as, 'HTTPS' \)"
prio:
    regex "Commit\("
prio:
    regex "!Ue\("
prio:
    regex "UserState0\("
prio:
    regex "UeConnect\("
prio:
    regex "\(~authz_code = authz_code\.1\)"
    regex "\(~authz_code = ~authz_code\.1\)"
    regex "\(~authz_code\.1 = ~authz_code\)"
prio:
    regex "!KU\( ~request\.3 \)"
prio:
    regex "!KU\( senc\(<<'HTTPS', ~as, 'authorize'"
prio:
    regex "!KU\( senc\(<<'HTTPS', ~as.*~state"
prio:
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "^BrowserSend\("
prio:
    regex "BrowserRecv\("
prio:
    regex ".*\(BrowserSend\("
prio:
    regex "\(AsSendAccessToken\("
prio:
    regex "AsState1\( ~as"
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "BrowserState0\("
prio:
    regex "!KU\( f1\(~k,.*~rand,"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3\(~k, ~rand"
prio:
    regex "!KU\( ~request\.4 \)"

tactic: weakagreement_as_hn
presort: C
prio:
    regex "SecureRecv\( ~client_secret"
prio:
    regex "!KU\( ~client_secret"
prio:
    regex "Commit\("
prio:
    regex "!AsClient\("
prio:
    regex "HttpServerRecv2\("

tactic: weakagreement_hn_as
presort: C
prio:
    regex "SecureRecv\( ~request"
prio:
    regex "!KU\( ~request"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "HttpClientRecv2\("

tactic: weakagreement_hn_user
presort: C
prio:
    regex "SecureRecv\( ~password"
    regex "SecureRecv\( ~request"
prio:
    regex "!KU\( ~password"
    regex "!KU\( ~request \)"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "HttpClientRecv2\("
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "BrowserRecv\("
prio:
    regex "BrowserState0\("

tactic: weakagreement_sn_hn
presort: C
prio:
    regex "Commit\("
prio:
    regex "SnState3\("

tactic: weakagreement_hn_sn
presort: C
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "SecureRecv\(.*<'auth_res'"

tactic: weakagreement_ue_hn
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "UeState2\("

tactic: weakagreement_hn_ue
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(<f3"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "SecureRecv\(.*<'auth_res'"

tactic: weakagreement_ue_sn
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "SecureRecv\(.*~sn,.*<'auth_req'"
prio:
    regex "UeState2\("
prio:
    regex "SecureRecv\(.*<'auth_req'"
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "!KU\( kdf\(<f3\(~k, rand\)"

tactic: weakagreement_sn_ue
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "!KU\( senc\('security_mode_complete'"
prio:
    regex "SecureRecv\(.*<'auth_req', rand"
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "SecureRecv\("
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3.*<~base"
prio:
    regex "SnState3\("

// --- Tactics: Non-Injective Agreement ---

tactic: noninjective_agreement_hn_id_as_user
presort: C
prio:
    regex "SecureRecv\( ~password"
prio:
    regex "!KU\( ~password"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "Commit\("
prio:
    regex "!User\("
prio:
    regex "AsState1\("
prio:
    regex "!AsClient\("
prio:
    regex "BrowserRecv\("
prio:
    regex "BrowserState0\("

tactic: noninjective_agreement_as_id_hn_user
presort: C
prio:
    regex "SecureRecv\( ~password"
    regex "SecureRecv\( ~request"
prio:
    regex "!KU\( ~request \)"
prio:
    regex "!KU\( ~password"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "HttpClientRecv2\("
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "BrowserRecv\("
prio:
    regex "BrowserState0\("

tactic: noninjective_agreement_as_id_user_hn
presort: C
prio:
    regex "SecureRecv\( ~k"
    regex "SecureRecv\( ~request"
prio:
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "HttpClientRecv\d\("
prio:
    regex "Rev\( ~ue, <'k', key> \).*Rev\( ~as, 'HTTPS' \)"
prio:
    regex "Commit\("
prio:
    regex "!Ue\("
prio:
    regex "UserState0\("
prio:
    regex "UeConnect\("
prio:
    regex "BrowserState0\( ~browser, ~ue, ~request \)"
prio:
    regex "\(~authz_code = authz_code\.1\)"
    regex "\(~authz_code = ~authz_code\.1\)"
    regex "\(~authz_code\.1 = ~authz_code\)"
prio:
    regex "!KU\( ~request\.3 \)"
prio:
    regex "!KU\( senc\(<<'HTTPS', ~as, 'authorize'"
prio:
    regex "!KU\( senc\(<<'HTTPS', ~as.*~state"
prio:
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "^BrowserSend\("
prio:
    regex "BrowserRecv\("
prio:
    regex ".*\(BrowserSend\("
prio:
    regex "\(AsSendAccessToken\("
prio:
    regex "AsState1\( ~as"
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "BrowserState0\("
prio:
    regex "!KU\( f1\(~k,.*~rand,"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3\(~k, ~rand"
prio:
    regex "!KU\( ~request\.4 \)"

tactic: noninjective_agreement_user_id_hn_as
presort: C
prio:
    regex "SecureRecv\( ~request"
prio:
    regex "!KU\( ~request"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "HttpClientRecv2\("

tactic: noninjective_agreement_sn_id_ue_hn
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3\(~k,"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "SecureRecv\(.*<'auth_req',.*~sn>"
prio:
    regex "UeState2\("
prio:
    regex "SecureRecv\("
prio:
    regex "!KU\( ~channel"

tactic: noninjective_agreement_sn_id_hn_ue
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "SecureRecv\("
prio:
    regex "!KU\( kdf\(<f3"

tactic: noninjective_agreement_supi_sn_hn
presort: C
prio:
    regex "Commit\("
prio:
    regex "SnState3\("

// --- Tactics: Injective Agreement ---

tactic: injective_agreement_access_token_hn_as
presort: C
prio:
    regex "SecureRecv\( ~access_token"
prio:
    regex "!KU\( ~access_token"
    regex "!KU\( ~request"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "HttpClientRecv2\("

tactic: injective_agreement_k_seaf_ue_hn
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "UeState2\("

tactic: injective_agreement_k_seaf_hn_ue
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "HnState1\("
prio:
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "!KU\( kdf\(<f3"
prio:
    regex "f1\(~k, <<~base.1, %incr_hn>"

tactic: injective_agreement_k_seaf_sn_hn
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "SnState3\("
prio:
    regex "!KU\( kdf\(kdf\(<f3\(~k, "
    regex "!KU\( kdf\(<f3\(~k, "

tactic: helper_injective_agreement_k_seaf_ue_sn
presort: C
prio:
    regex "Commit\("
prio:
    regex "UeState2\("

tactic: injective_agreement_k_seaf_ue_sn
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3\(~k, rand\)"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "!KU\( senc\('security_mode_command'"
prio:
    regex "UeState2\("
prio:
    regex "SecureRecv\(.*<'auth_req',.*~sn>"

tactic: helper_injective_agreement_k_seaf_sn_ue
presort: C
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3.*<~base"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "SnState3\("

tactic: injective_agreement_k_seaf_sn_ue
presort: C
prio:
    regex "Honest\( Z \) @ #i"
prio:
    regex "SecureRecv\( ~k"
prio:
    regex "!KU\( kdf\(kdf"
    regex "!KU\( kdf\(<f3.*<~base"
    regex "!KU\( f3\(~k"
    regex "!KU\( ~k"
prio:
    regex "Commit\("
prio:
    regex "!KU\( senc\('security_mode_complete'"
prio:
    regex "SecureRecv\(.*<'auth_req', rand"
    regex "SecureRecv\(.*<'auth_res'"
prio:
    regex "SnState3\("

// --- Secure Channel ---

rule secure_send:
    [ SecureSend(~channel, A, B, m) ]
  -->
    [ SecureMessage(~channel, A, B, m) ]

rule secure_recv:
    [ SecureMessage(~channel, A, B, m) ]
  -->
    [ SecureRecv(~channel, A, B, m) ]

rule secure_adversary_send:
    [ In(<~channel, A, B, m>) ]
  --[ Rev(A, 'channel')
    , Rev(B, 'channel')
    , AdversaryChannelSend(~channel)
    , AdversaryInject(m)
    ]->
    [ SecureMessage(~channel, A, B, m) ]

rule secure_adversary_recv:
    [ SecureMessage(~channel, A, B, m) ]
  --[ Rev(A, 'channel')
    , Rev(B, 'channel')
    , AdversaryChannelRecv(~channel)
    ]->
    [ Out(<~channel, m>) ]

// --- HTTPS ---

m4_for(`iter', `0', MAX_HTTP, `
rule https_send`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ In(server)
    , HttpClientSend`'iter`'(~request, url, message)
    ]
  -->
    [ HttpServerRecv`'iter`'(~request, url, message) ]

rule https_recv`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ HttpServerSend`'iter`'(~request, url, message) ]
  -->
    [ HttpClientRecv`'iter`'(~request, url, message) ]

rule https_adverary_client_send`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ In(<~request, url, message>) ]
  --[ Rev(server, m4_const(HTTPS)) ]->
    [ HttpClientSend`'iter`'(~request, url, message) ]

rule https_adverary_client_recv`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ HttpClientRecv`'iter`'(~request, url, message) ]
  --[ Rev(server, m4_const(HTTPS)) ]->
    [ Out(<~request, url, message>) ]

rule https_adverary_server_send`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ In(<~request, url, message>) ]
  --[ Rev(server, m4_const(HTTPS)) ]->
    [ HttpServerSend`'iter`'(~request, url, message) ]

rule https_adverary_server_recv`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ HttpServerRecv`'iter`'(~request, url, message) ]
  --[ Rev(server, m4_const(HTTPS)) ]->
    [ Out(<~request, url, message>) ]

rule https_adverary_send_honest`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ Fr(~request)
    , In(<url, message>)
    ]
  -->
    [ HttpServerRecv`'iter`'(~request, url, message)
    , AdversaryRequest(~request)
    ]

rule https_adverary_recv_honest`'iter:
  let url = <m4_const(HTTPS), server, $path>
  in
    [ HttpClientRecv`'iter`'(~request, url, message)
    , AdversaryRequest(~request)
    ]
  -->
    [ Out(<url, message>) ]
')

// --- AS ---

rule as_create:
  let
    public = <~as, pk(~sk_as)>
  in
    [ Fr(~as)
    , Fr(~sk_as)
    ]
  -->
    [ Out(public)
    , !As(~as, ~sk_as)
    ]

rule as_user_create:
    [ Fr(~user)
    , Fr(~password)
    , !As(~as, ~sk_as)
    ]
  --[ AsUserCreate(~as, ~user) ]->
    [ !User(~user, ~as, ~password) ]

rule as_client_register:
    [ Fr(~client)
    , Fr(~client_secret)
    , !Hn(~hn, ~sk)
    , !As(~as, ~sk_as)
    ]
  --[ AsClientRegister(~as, ~hn) ]->
    [ Out(~client)
    , !AsClient(~as, ~hn, ~client, ~client_secret)
    ]

rule as_recv_authorization_request:
  let
    url     = <'HTTPS', ~as, 'authorize'>
    params  = <hn_url, ~client, state, code_challenge>
    msg_in  = <'GET', params>
    webpage = <'login', ~hn>
    msg_out = <'200', webpage>
  in
    [ Fr(~session_cookie)
    , HttpServerRecv0(~request, url, <msg_in, ignored_cookie>)
    , !AsClient(~as, ~hn, ~client, ~client_secret)
    , !As(~as, ~sk_as)
    ]
  --[ _restrict(hn_url = <'BYOI', 'null', 'callback'>)
    , AsCookieSet(~session_cookie)
    , AsRecvAuthorizationRequest(~as, ~request, ~session_cookie)
    , SessionStart(~as, ~session_cookie)
    ]->
    [ HttpServerSend0(~request, url, <msg_out, ~session_cookie>)
    , AsState0(~as, ~session_cookie, hn_url, ~client, state, code_challenge)
    ]

rule as_recv_user_credentials:
  let
    url     = <'HTTPS', ~as, 'authorize'>
    msg_in  = <'POST', ~user, ~password>
    msg_out = <'302', hn_url, <~authz_code, state, ~hn>>
  in
    [ Fr(~authz_code)
    , HttpServerRecv1(~request, url, <msg_in, ~session_cookie>)
    , AsState0(~as, ~session_cookie, hn_url, ~client, state, code_challenge)
    , !User(~user, ~as, ~password)
    , !AsClient(~as, ~hn, ~client, ~client_secret)
    , !As(~as, ~sk_as)
    ]
  --[ AsRecvUserCredentials()
    , AsSendAuthzCode(~authz_code)
    , SessionAdvance(~as, ~session_cookie)
    , Secret(~as, <'user',       ~user      >)
    , Secret(~as, <'password',   ~password  >)
    , Secret(~as, <'authz_code', ~authz_code>)
    , Honest(~user)
    , Honest(~hn)
    , Honest(~as)
    ]->
    [ HttpServerSend1(~request, url, <msg_out, ~session_cookie>)
    , AsState1(~as, ~session_cookie, ~client, code_challenge, ~user, ~authz_code)
    ]

rule as_recv_access_token_request:
  let
    url      = <'HTTPS', ~as, 'token'>
    msg_in   = <'POST', ~authz_code, ~client_secret, code_verifier>
    id_token = <~user, sign(~user, ~sk_as)>
    webpage  = <~access_token, id_token>
    msg_out  = <'200', webpage>
 in
    [ Fr(~access_token)
    , HttpServerRecv2(~request, url, <msg_in, ignored_cookie>)
    , AsState1(~as, ~session_cookie, ~client, code_challenge, ~user, ~authz_code)
    , !User(~user, ~as, ~password)
    , !AsClient(~as, ~hn, ~client, ~client_secret)
    , !As(~as, ~sk_as)
    ]
  --[ AsRecvAccessTokenRequest()
    , AsSendAccessToken(~as, ~authz_code)
    , PkceCheck(~as, h(code_verifier), code_challenge)
    , AsCookieSet('null')
    , SessionAdvance(~as, ~session_cookie)
    , Commit(~as, ~user, <'as', 'user', <'hn',   ~hn  >>)
    , Commit(~as, ~hn,   <'as', 'hn',   <'user', ~user>>)
    , Running(~as, ~user, <'as', 'user', <'hn',           ~hn          >>)
    , Running(~as, ~hn,   <'as', 'hn',   <'user',         ~user        >>)
    , Running(~as, ~hn,   <'as', 'hn',   <'access_token', ~access_token>>)
    , Secret(~as, <'client_secret', ~client_secret>)
    , Secret(~as, <'authz_code',    ~authz_code   >)
    , Secret(~as, <'access_token',  ~access_token >)
    , Honest(~user)
    , Honest(~hn)
    , Honest(~as)
    ]->
    [ HttpServerSend2(~request, url, <msg_out, 'null'>) ]

// --- HN ---

rule hn_create:
  let
    public = <~hn, pk(~sk)>
  in
    [ Fr(~hn)
    , Fr(~sk)
    ]
  -->
    [ Out(public)
    , !Hn(~hn, ~sk)
    ]

rule hn_recv_authentication_request:
  let
    suci           = <aenc(<~ue,  ~nonce0>, pk(~sk)), ~hn>
    byoi           = <aenc(<user, ~nonce1>, pk(~sk)), ~as>
    snid           = <'5G', ~sn>
    msg_in         = <suci, byoi, snid>

    sqn_next       = <~base, %incr %+ %1>

    mac            = f1(~k, <sqn_next, ~rand, snid>)
    xres           = f2(~k, ~rand)
    ck             = f3(~k, ~rand)
    ik             = f4(~k, ~rand)
    ak             = f5(~k, ~rand)

    autn           = <sqn_next XOR ak, mac>

    k_ausf         = kdf(<ck, ik>, <snid, sqn_next XOR ak>)
    k_seaf         = kdf(k_ausf, snid)

    xres_star      = kdf(<ck, ik>, <snid, xres, ~rand>)
    hxres_star     = h(<xres_star, ~rand>)

    ek_hn          = kdf(<ck, ik>, '5GBYOIEKHN')
    ek_ue          = kdf(<ck, ik>, '5GBYOIEKUE')
    as_url         = <'HTTPS', ~as, 'authorize'>
    hn_url         = <'BYOI', 'null', 'callback'>
    code_challenge = h(~code_verifier)
    as_params      = <hn_url, ~client, ~state, code_challenge>
    url            = senc(<as_url, as_params>, ek_hn)

    msg_out        = <~rand, hxres_star, autn, url>
  in
    [ Fr(~session)
    , Fr(~rand)
    , Fr(~state)
    , Fr(~code_verifier)
    , SecureRecv(~channel, ~sn, ~hn, <'auth_req', msg_in>)
    , HnSqn(~hn, ~ue, <~base, %incr>)
    , !AsClient(~as, ~hn, ~client, ~client_secret)
    , !As(~as, ~sk_as)
    , !Ue(~ue, ~hn, ~k)
    , !Sn(~sn, ~hn, snid_sn)
    , !Hn(~hn, ~sk)
    ]
  --[ HnStart(~hn)
    , HnAuthRequest(~rand, autn, url)
    , HnSqnUse(~hn, ~base)
    , HnSendAsParams(as_params)
    , HnSendAuthReq(~hn, ~ue)
    , SessionStart('hn', ~session)
    , Secret(~hn, <'supi', ~ue>)
    , Honest(~ue)
    , Honest(~hn)
    ]->
    [ SecureSend(~channel, ~hn, ~sn, <'auth_req', msg_out>)
    , HnState0(~hn, ~session, ~channel, ~ue, ~as, ~rand, k_seaf, xres_star, ek_ue, ~state, ~code_verifier)
    , HnSqn(~hn, ~ue, sqn_next)
    ]

rule hn_recv_sync_failure:
  let
    sqn_ue   = <~base, %incr_ue>

    aks      = f5_star(~k, ~rand)
    macs     = f1_star(~k, <sqn_ue, ~rand>)
    auts     = <sqn_ue XOR aks, macs>

    msg_in   = <~rand, auts>
  in
    [ SecureRecv(~channel, ~sn, ~hn, <'auth_resync', msg_in>)
    , HnState0(~hn, ~session, ~channel, ~ue, ~as, ~rand, k_seaf, xres_star, ek_ue, ~state, ~code_verifier)
    , HnSqn(~hn, ~ue, <~base, %incr>)
    , !Ue(~ue, ~hn, ~k)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ _restrict(%incr << %incr_ue)
    , HnSqnUse(~hn, ~base)
    ]->
    [ HnSqn(~hn, ~ue, <~base, %incr>) ]

rule hn_recv_authentication_response:
  let
    code       = senc(<authz_code, ~state>, ek_ue)
    msg_in     = <xres_star, code>

    url        = <'HTTPS', ~as, 'token'>
    msg_out    = <'POST', authz_code, ~client_secret, ~code_verifier>
  in
    [ Fr(~request)
    , SecureRecv(~channel, ~sn, ~hn, <'auth_res', msg_in>)
    , HnState0(~hn, ~session, ~channel, ~ue, ~as, ~rand, k_seaf, xres_star, ek_ue, ~state, ~code_verifier)
    , !AsClient(~as, ~hn, ~client, ~client_secret)
    , !As(~as, ~sk_as)
    , !Ue(~ue, ~hn, ~k)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ HnSendAuthzCode(authz_code)
    , SessionAdvance('hn', ~session)
    , Running(~hn, ~as,  <'hn', 'as', 'weakagreement'>)
    , Secret(~hn, <'client_secret', ~client_secret>)
    , Honest(~ue)
    , Honest(~hn)
    , Honest(~as)
    ]->
    [ HttpClientSend2(~request, url, <msg_out, 'null'>)
    , HnState1(~hn, ~session, ~channel, ~ue, ~as, ~rand, k_seaf, ~request, ~channel, ~sn, authz_code)
    ]

rule hn_recv_access_token:
  let
    id_token = <user, sig>
    webpage  = <access_token, id_token>
    msg_in   = <'200', webpage>

    msg_out  = <~ue, k_seaf>
  in
    [ HttpClientRecv2(~request, url, <msg_in, ignored_cookie>)
    , HnState1(~hn, ~session, ~channel, ~ue, ~as, ~rand, k_seaf, ~request, ~channel, ~sn, authz_code)
    , !As(~as, ~sk_as)
    , !Ue(~ue, ~hn, ~k)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ _restrict(verify(sig, user, pk(~sk_as)) = true)
    , HnRecvAccessToken(~ue, ~as, authz_code, ~rand)
    , HnSendAuthConfirm(~hn, ~sn)
    , SessionAdvance('hn', ~session)
    , Commit(~hn,  user, <'hn', 'user', <'as',          ~as          >>)
    , Commit(~hn, ~ue,   <'hn', 'ue',   <'sn',          ~sn          >>)
    , Commit(~hn, ~ue,   <'hn', 'ue',   <'k_seaf',       k_seaf      >>)
    , Commit(~hn, ~sn,   <'hn', 'sn',    'weakagreement'              >)
    , Commit(~hn, ~as,   <'hn', 'as',   <'user',         user        >>)
    , Commit(~hn, ~as,   <'hn', 'as',   <'access_token', access_token>>)
    , Running(~hn,  user, <'hn', 'user', <'as',     ~as    >>)
    , Running(~hn, ~ue,   <'hn', 'ue',   <'sn',     ~sn    >>)
    , Running(~hn, ~ue,   <'hn', 'ue',   <'k_seaf',  k_seaf>>)
    , Running(~hn, ~sn,   <'hn', 'sn',   <'ue',     ~ue    >>)
    , Running(~hn, ~sn,   <'hn', 'sn',   <'k_seaf',  k_seaf>>)
    , Secret(~hn, <'k_seaf', k_seaf>)
    , Honest(~ue)
    , Honest(~sn)
    , Honest(~hn)
    , Honest(~as)
    ]->
    [ SecureSend(~channel, ~hn, ~sn, <'auth_confirm', msg_out>) ]

// --- SN ---

rule sn_create:
  let
    snid   = <'5G', ~sn>
    public = snid
  in
    [ Fr(~sn)
    , !Hn(~hn, ~sk)
    ]
  -->
    [ Out(public)
    , !Sn(~sn, ~hn, snid)
    ]

rule sn_recv_registration_request:
  let
    suci     = <supi_enc, ~hn>
    msg_in   = <suci, byoi>
    msg_out  = <suci, byoi, snid>
  in
    [ Fr(~channel)
    , In(msg_in)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ SnChannelCreate(~channel) ]->
    [ SecureSend(~channel, ~sn, ~hn, <'auth_req', msg_out>)
    , SnState0(~sn, ~hn, ~channel)
    ]

rule sn_recv_authentication_request:
  let
    msg_in  = <rand, hxres_star, autn, url>
    snid    = <'5G', ~sn>
    msg_out = <rand, autn, snid, url>
  in
    [ SecureRecv(~channel, ~hn, ~sn, <'auth_req', msg_in>)
    , SnState0(~sn, ~hn, ~channel)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ SnAuthRequest(rand, autn, url) ]->
    [ Out(msg_out)
    , SnState1(~sn, ~hn, ~channel, hxres_star, rand)
    ]

rule sn_recv_authentication_response:
  let
    msg_in     = <res_star, code>
    hxres_star = h(<res_star, rand>)
    msg_out    = msg_in
  in
    [ In(msg_in)
    , SnState1(~sn, ~hn, ~channel, hxres_star, rand)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ Running(~sn, ~hn, <'sn', 'hn', 'weakagreement'>) ]->
    [ SecureSend(~channel, ~sn, ~hn, <'auth_res', msg_out>)
    , SnState2(~sn, ~hn, ~channel)
    ]

rule sn_recv_sync_failure:
  let
    msg_out = <rand, msg_in>
  in
    [ In(msg_in)
    , SnState1(~sn, ~hn, ~channel, hxres_star, rand)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  -->
    [ SecureSend(~channel, ~sn, ~hn, <'auth_resync', msg_out>) ]

rule sn_recv_authentication_confirm:
  let
    msg_in  = <~ue, k_seaf>
    msg_out = senc('security_mode_command', k_seaf)
  in
    [ SecureRecv(~channel, ~hn, ~sn, <'auth_confirm', msg_in>)
    , SnState2(~sn, ~hn, ~channel)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ SnRecvAuthenticationConfirm(~sn)
    , Running(~sn, ~ue, <'sn', 'ue', <'hn',     ~hn    >>)
    , Running(~sn, ~ue, <'sn', 'ue', <'k_seaf',  k_seaf>>)
    , Secret(~sn, <'supi_sn', ~ue   >)
    , Secret(~sn, <'k_seaf',  k_seaf>)
    , Honest(~ue)
    , Honest(~sn)
    , Honest(~hn)
    ]->
    [ Out(msg_out)
    , SnState3(~sn, ~hn, k_seaf, ~ue)
    ]

rule sn_recv_security_mode_complete:
  let
    msg_in = senc('security_mode_complete', k_seaf)
  in
    [ In(msg_in)
    , SnState3(~sn, ~hn, k_seaf, ~ue)
    , !Sn(~sn, ~hn, snid)
    , !Hn(~hn, ~sk)
    ]
  --[ SnRecvSecurityModeComplete()
    , Commit(~sn, ~ue, <'sn', 'ue', <'hn',     ~hn    >>)
    , Commit(~sn, ~ue, <'sn', 'ue', <'k_seaf',  k_seaf>>)
    , Commit(~sn, ~hn, <'sn', 'hn', <'ue',     ~ue    >>)
    , Commit(~sn, ~hn, <'sn', 'hn', <'k_seaf',  k_seaf>>)
    , Honest(~ue)
    , Honest(~sn)
    , Honest(~hn)
    ]->
    []

// --- UE ---

rule ue_create:
    [ Fr(~ue)
    , Fr(~k)
    , Fr(~base)
    , Fr(~pid)
    , !Hn(~hn, ~sk)
    ]
  --[ UeSqnCreate(~ue, ~base)
    , HnSqnCreate(~hn, ~base)
    ]->
    [ UePossession(~pid, ~ue, 'null')
    , UeSqn(~ue, <~base, %1>)
    , HnSqn(~hn, ~ue, <~base, %1>)
    , !Ue(~ue, ~hn, ~k)
    , !UeSqnBase(~ue, ~base)
    ]

rule ue_user_possess:
    [ Fr(~pid)
    , UePossession(old_pid, ~ue, old_user)
    , !User(~user, ~as, ~password)
    ]
  --[ UePossess(~ue) ]->
    [ UePossession(~pid, ~ue, ~user) ]

rule ue_adversary_possess:
    [ Fr(~pid)
    , UePossession(old_pid, ~ue, old_user)
    ]
  --[ UePossess(~ue) ]->
    [ UePossession(~pid, ~ue, 'adversary') ]

rule ue_send_registration_request:
  let
    suci    = <aenc(<~ue,    ~nonce0>, pk(~sk)), ~hn>
    byoi    = <aenc(<'null', ~nonce1>, pk(~sk)), ~as>
    msg_out = <suci, byoi>
  in
    [ Fr(~session)
    , Fr(~nonce0)
    , Fr(~nonce1)
    , UePossession(~pid, ~ue, ~user)
    , !User(~user, ~as, ~password)
    , !As(~as, ~sk_as)
    , !Ue(~ue, ~hn, ~k)
    , !Hn(~hn, ~sk)
    ]
  --[ UeStart(~ue)
    , Secret(~ue, <'supi', ~ue>)
    , Honest(~ue)
    , Honest(~hn)
    ]->
    [ Out(msg_out)
    , UeState0(~ue, ~session, ~as, ~hn)
    , UePossession(~pid, ~ue, ~user)
    ]

rule ue_recv_authentication_request:
  let
    sqn_hn   = <~base, %incr_hn>

    snid     = <'5G', sn>
    mac      = f1(~k, <sqn_hn, rand, snid>)

    ak       = f5(~k, rand)
    autn     = <sqn_hn XOR ak, mac>

    ck       = f3(~k, rand)
    ik       = f4(~k, rand)
    ek_ue    = kdf(<ck, ik>, '5GBYOIEKUE')
    ek_hn    = kdf(<ck, ik>, '5GBYOIEKHN')
    as_params = <hn_url, hn_client, oauth_state, code_challenge>
    as_url   = <protocol, hn_as, file>
    url      = senc(<as_url, as_params>, ek_hn)

    msg_in   = <rand, autn, snid, url>

    res      = f2(~k, rand)
    res_star = kdf(<ck, ik>, <snid, res, rand>)
    k_ausf   = kdf(<ck, ik>, <snid, sqn_hn XOR ak>)
    k_seaf   = kdf(k_ausf, snid)
  in
    [ Fr(~sid)
    , In(msg_in)
    , UeState0(~ue, ~session, exp_as, ~hn)
    , UeSqn(~ue, <~base, %incr>)
ifdef(`USER_SESSION_PID', `
    , UePossession(~pid, ~ue, ~user)
', `
    , Fr(~pid)
')
    , !Ue(~ue, ~hn, ~k)
    , !Hn(~hn, ~sk)
    ]
  --[ _restrict(%incr << %incr_hn)
    , UeAsCheck(~ue, hn_as, exp_as)
    , UeBrowserStart(url, as_params)
    , UeSqnUse(~ue, ~base)
    , UeSqnValueUpdate(~ue, %incr_hn)
    , UeAuthReqAs(~ue, hn_as, ~sid, ~session, oauth_state)
    , Secret(~ue, <'k_seaf', k_seaf>)
    , Honest(~ue)
    , Honest(sn)
    , Honest(~hn)
    ]->
    [ BrowserStart(~ue, ~sid, as_url, <'GET', as_params>)
    , UeState1(~ue, ~session, ~hn, ~sid, oauth_state, res_star, ek_ue, k_seaf, sn, rand)
    , UeSqn(~ue, <~base, %incr_hn>)
ifdef(`USER_SESSION_PID', `
    , UePossession(~pid, ~ue, ~user)
')
    , UserStateMinus1(~user, ~pid, ~sid, hn_as)
    ]

rule ue_recv_authentication_request_sync_failure:
  let
    sqn_hn   = <~base, %incr_hn>

    snid     = <'5G', sn>
    mac      = f1(~k, <sqn_hn, rand, snid>)

    ak       = f5(~k, rand)
    autn     = <sqn_hn XOR ak, mac>

    msg_in   = <rand, autn, snid, url>

    aks      = f5_star(~k, rand)
    sqn_ue   = <~base, %incr>
    macs     = f1_star(~k, <sqn_ue, rand>)
    auts     = <sqn_ue XOR aks, macs>

    msg_out  = auts
  in
    [ In(msg_in)
    , UeState0(~ue, ~session, exp_as, ~hn)
    , UeSqn(~ue, <~base, %incr>)
    , !Ue(~ue, ~hn, ~k)
    , !Hn(~hn, ~sk)
    ]
  --[ _restrict(not(%incr << %incr_hn))
    , UeSqnUse(~ue, ~base)
    , UeSqnValue(~ue, %incr)
    ]->
    [ Out(msg_out)
    , UeSqn(~ue, <~base, %incr>)
    ]

rule ue_send_user_credentials:
  let
    url_in  = <'HTTPS', ~as, $path>
    url_out = <'HTTPS', ~as, 'authorize'>
    msg_in  = <'login', id_hn>
    msg_out = <'POST', ~user, ~password>
  in
    [ BrowserLoaded0(~browser, ~ue, url_in, msg_in)
    , UePossession(~pid, ~ue, ~user)
ifdef(`USER_SESSION_PID', `
    , UserStateMinus1(~user, ~pid_state, ~sid, as_state)
', `
    , Fr(~sid)
')
    , !User(~user, ~as, ~password)
    , !Browser(~browser, ~ue, bid)
    , !Ue(~ue, ~hn, ~k)
    ]
  --[ UeSendUserCredentials(~ue, ~user)
    , UserSendCredentials(~user, ~ue, ~sid, bid)
ifdef(`USER_SESSION_PID', `
    , UserEqualCheck(~user, ~as, as_state)
    , UserEqualCheck(~user, ~sid, bid)
')
    , Secret(~user, <'user',     ~user    >)
    , Secret(~user, <'password', ~password>)
    , Running(~user, id_hn, <'user', 'hn', <'as', ~as  >>)
    , Running(~user, ~as,   <'user', 'as', <'hn', id_hn>>)
    , Honest(~user)
    , Honest(~as)
    ]->
    [ BrowserRequest1(~browser, ~ue, url_out, msg_out)
    , UePossession(~pid, ~ue, ~user)
    , UserState0(~user, ~pid, ~sid, ~ue, ~as, id_hn)
    ]

rule ue_recv_authorization_redirect:
  let
    url     = <'BYOI', 'null', 'callback'>
    msg_in  = <'GET', <authz_code, hn_oauth_state, hn_as>>
    code    = senc(<authz_code, hn_oauth_state>, ek_ue)
    msg_out = <res_star, code>
  in
    [ BrowserRequest2(~browser, ~ue, url, msg_in)
    , UeState1(~ue, ~session, ~hn, ~sid, oauth_state, res_star, ek_ue, k_seaf, sn, rand)
    , !Browser(~browser, ~ue, bid)
    , !Ue(~ue, ~hn, ~k)
    ]
  --[ UeRecvAuthorizationRedirect(~ue, authz_code, rand)
    , UeOauthStateCheck(~ue, hn_oauth_state, oauth_state)
    , Running(~ue, ~hn, <'ue', 'hn', <'sn',     sn    >>)
    , Running(~ue, ~hn, <'ue', 'hn', <'k_seaf', k_seaf>>)
    ]->
    [ Out(msg_out)
    , UeAuthzCode(~ue, authz_code)
    , UeState2(~ue, ~session, ~hn, ~sid, k_seaf, sn)
    ]

rule ue_reveal_authz_code:
    [ UeAuthzCode(~ue, authz_code) ]
  --[ Rev(~ue, <'authz_code', authz_code>) ]->
    [ Out(authz_code) ]

rule ue_recv_security_mode_command:
  let
    msg_in  = senc('security_mode_command',  k_seaf)
    msg_out = senc('security_mode_complete', k_seaf)
  in
    [ In(msg_in)
    , UeState2(~ue, ~session, ~hn, ~sid, k_seaf, sn)
    , !Ue(~ue, ~hn, ~k)
    ]
  --[ Commit(~ue,  sn, <'ue',   'sn', <'hn',     ~hn    >>)
    , Commit(~ue,  sn, <'ue',   'sn', <'k_seaf',  k_seaf>>)
    , Commit(~ue, ~hn, <'ue',   'hn', <'sn',      sn    >>)
    , Commit(~ue, ~hn, <'ue',   'hn', <'k_seaf',  k_seaf>>)
    , Running(~ue, sn, <'ue', 'sn', <'hn',     ~hn    >>)
    , Running(~ue, sn, <'ue', 'sn', <'k_seaf',  k_seaf>>)
    , Honest(~ue)
    , Honest(sn)
    , Honest(~hn)
    ]->
    [ Out(msg_out)
    , UeConnect(~ue, ~sid, ~session)
    ]

rule user_connect:
    [ UeConnect(~ue, ~sid, ~session)
    , UePossession(~pid, ~ue, ~user)
    , UserState0(~user, ~pid_state, ~sid_state, ~ue, id_as, id_hn)
    , !User(~user, ~as, ~password)
    , !Ue(~ue, ~hn, ~k)
    ]
  --[ UserConnect(~user, ~ue, ~sid)
    , UserEqualCheck(~user, ~pid, ~pid_state)
    , UserEqualCheck(~user, ~sid, ~sid_state)
    , Commit(~user, id_hn, <'user', 'hn', <'as', id_as>>)
    , Commit(~user, id_as, <'user', 'as', <'hn', id_hn>>)
    , Honest(~user)
    , Honest(~ue)
    , Honest(id_hn)
    , Honest(id_as)
    ]->
    [ UePossession(~pid, ~ue, ~user) ]

// --- Browser ---

rule browser_launch:
let
    url = <$protocol, server, $path>
in
    [ Fr(~request)
    , Fr(~browser)
    , BrowserStart(~ue, bid, url, msg)
    , !Ue(~ue, ~hn, ~k)
    ]
  --[ BrowserSend(~request, ~ue, server, 'null', ~browser) ]->
    [ HttpClientSend0(~request, url, <msg, 'null'>)
    , BrowserState0(~browser, ~ue, ~request)
    , !Browser(~browser, ~ue, bid)
    ]

rule browser_cookie_create:
    [ In(server)
    , !Browser(~browser, ~ue, bid)
    ]
  --[ BrowserCookieCreate(server, 'null') ]->
    [ BrowserCookie(~browser, server, 'null') ]

m4_for(`iter', `1', MAX_HTTP, `
rule browser_request`'iter:
let
    url = <$protocol, server, $path>
in
    [ Fr(~request)
    , BrowserRequest`'iter`'(~browser, ~ue, url, msg)
    , BrowserState1(~browser, ~ue)
    , BrowserCookie(~browser, server, cookie)
    , !Browser(~browser, ~ue, bid)
    ]
  --[ BrowserCookieSend(cookie)
    , BrowserSend(~request, ~ue, server, cookie, ~browser)
    ]->
    [ HttpClientSend`'iter`'(~request, url, <msg, cookie>)
    , BrowserState0(~browser, ~ue, ~request)
    , BrowserCookie(~browser, server, cookie)
    ]
')

m4_for(`iter', `0', MAX_HTTP, `
rule browser_ok_handler`'iter:
  let
    url    = <$protocol, server, $path>
    msg_in = <m4_const(200), webpage>
  in
    [ HttpClientRecv`'iter`'(~request, url, <msg_in, cookie>)
    , BrowserState0(~browser, ~ue, ~request)
    , BrowserCookie(~browser, server, old_cookie)
    , !Browser(~browser, ~ue, bid)
    ]
  --[ BrowserRecv(~request, ~ue, server, cookie, ~browser) ]->
    [ BrowserLoaded`'iter`'(~browser, ~ue, url, webpage)
    , BrowserState1(~browser, ~ue)
    , BrowserCookie(~browser, server, cookie)
    ]
')

m4_for(`iter', `0', decr(MAX_HTTP), `
rule browser_redirect_handler`'iter:
  let
    url     = <$protocol, server, $path>
    msg_in  = <m4_const(302), redirect_url, redirect_params>
    msg_out = <m4_const(GET), redirect_params>
  in
    [ HttpClientRecv`'iter`'(~request, url, <msg_in, cookie>)
    , BrowserState0(~browser, ~ue, ~request)
    , BrowserCookie(~browser, server, old_cookie)
    , !Browser(~browser, ~ue, bid)
    ]
  --[ BrowserRecv(~request, ~ue, server, cookie, ~browser) ]->
    [ BrowserRequest`'incr(iter)`'(~browser, ~ue, redirect_url, msg_out)
    , BrowserState1(~browser, ~ue)
    , BrowserCookie(~browser, server, cookie)
    ]
')

// --- Secret Compromise ---

rule reveal_as_sk:
    [ !As(~as, ~sk_as) ]
  --[ Rev(~as, <'sk_as', ~sk_as>) ]->
    [ Out(~sk_as) ]

rule reveal_as_user_id:
    [ !User(~user, ~as, ~password) ]
  --[ Rev(~user, <'user', ~user>)
    , Rev(~as,   <'user', ~user>)
    ]->
    [ Out(~user) ]

rule reveal_as_user_password:
    [ !User(~user, ~as, ~password) ]
  --[ Rev(~user, <'password', ~password>)
    , Rev(~as,   <'password', ~password>)
    ]->
    [ Out(~password) ]

rule reveal_as_client_secret:
    [ !AsClient(~as, ~hn, ~client, ~client_secret) ]
  --[ Rev(~as, <'client_secret', ~client_secret>)
    , Rev(~hn, <'client_secret', ~client_secret>)
    ]->
    [ Out(<~client_secret>) ]

rule reveal_hn_sk:
    [ !Hn(~hn, ~sk) ]
  --[ Rev(~hn, <'sk_hn', ~sk>) ]->
    [ Out(~sk) ]

rule reveal_ue_id:
    [ !Ue(~ue, ~hn, ~k) ]
  --[ Rev(~ue, <'supi', ~ue>)
    , Rev(~hn, <'supi', ~ue>)
    ]->
    [ Out(~ue) ]

rule reveal_ue_k:
    [ !Ue(~ue, ~hn, ~k) ]
  --[ Rev(~ue, <'k', ~k>)
    , Rev(~hn, <'k', ~k>)
    ]->
    [ Out(~k) ]

rule reveal_ue_sqn_base:
    [ !Ue(~ue, ~hn, ~k)
    , !UeSqnBase(~ue, ~base)
    ]
  --[ Rev(~ue, <'sqn', ~base>)
    , Rev(~hn, <'sqn', ~base>)
    ]->
    [ Out(~base) ]

rule init_done:
    [] --[ InitDone() ]-> []

// --- Restrictions ---

restriction as_client_register_once:
    " All as hn #i #j.
        AsClientRegister(as, hn)@i & AsClientRegister(as, hn)@j ==> #i = #j "

restriction browser_cookie_create_once:
    " All server cookie1 cookie2 #i #j.
        BrowserCookieCreate(server, cookie1)@i
      & BrowserCookieCreate(server, cookie2)@j
            ==> #i = #j "

restriction init_done_once:
    " All #i #j. InitDone()@i & InitDone()@j ==> #i = #j "

// --- Sources ---

// Proven (< 1 min)
lemma source_ue_sqn[sources, reuse, heuristic={source_ue_hn_sqn}]:
    " All #i ue base. UeSqnUse(ue, base)@i ==> (Ex #j. UeSqnCreate(ue, base)@j & #j < #i) "

// Proven (< 1 min)
lemma source_hn_sqn[sources, reuse, heuristic={source_ue_hn_sqn}]:
    " All #i hn base. HnSqnUse(hn, base)@i ==> (Ex #j. HnSqnCreate(hn, base)@j & #j < #i) "

// Proven (12 min)
lemma source_ue_cookie[sources, reuse, heuristic={source_ue_cookie}]:
    " All cookie #i. BrowserCookieSend(cookie)@i
        ==> (Ex        #j. AsCookieSet(cookie)@j                 & #j < #i)
          | (Ex server #j. BrowserCookieCreate(server, cookie)@j & #j < #i)
          | (Ex        #j. KU(cookie)@j                          & #j < #i) "

// Proven (12 min)
lemma source_hn_authz_code_ue_as_params_combined[sources, reuse, heuristic={source_hn_authz_code_ue_as_params_combined}]:
    "( All authz_code #i. HnSendAuthzCode(authz_code)@i
        ==> (Ex #j. AsSendAuthzCode(authz_code)@j & #j < #i)
          | (Ex #j. HnSendAsParams(authz_code)@j  & #j < #i)
          | (Ex #j. KU(authz_code)@j              & #j < #i)
          | (authz_code = 'security_mode_command'               ) ) &
     ( All url params #i. UeBrowserStart(url, params)@i
        ==> (Ex #j. HnSendAsParams(params)@j & #j < #i)
          | (Ex #j. KU(params)@j             & #j < #i) )"

// Proven (1 min)
lemma source_sn_auth_request[sources, heuristic={source_sn_auth_request}]:
    " All rand autn url #i. SnAuthRequest(rand, autn, url)@i
        ==> (Ex            #j. HnAuthRequest(rand, autn, url)@j                             & #j < #i)
          | (Ex hxres_star #j. AdversaryInject(<'auth_req', rand, hxres_star, autn, url>)@j & #j < #i) "

define(`hide_lemmas_sources', `                              dnl
      hide_lemma=source_ue_sqn                               dnl
    , hide_lemma=source_hn_sqn                               dnl
    , hide_lemma=source_ue_cookie                            dnl
    , hide_lemma=source_hn_authz_code_ue_as_params_combined  dnl
')

// --- Helpers ---

// Proven (28 min)
lemma helper_browser_request_matching[reuse, heuristic={helper_browser_request_matching}, hide_lemmas_sources]:
    " All request ue1 ue2 as1 as2 cookie1 cookie2 browser1 browser2 #i #j.
        BrowserSend(request, ue1, as1, cookie1, browser1)@i
                & BrowserRecv(request, ue2, as2, cookie2, browser2)@j
            ==> (ue1 = ue2) & (browser1 = browser2) "

// Proven (15 min)
lemma helper_browser_cookie_matching1[reuse, use_induction, heuristic={helper_browser_cookie_matching1}, hide_lemmas_sources]:
    " All request1 ue as cookie browser #i. BrowserSend(request1, ue, as, cookie, browser)@i
        ==> (Ex request2 #j. BrowserRecv(request2, ue, as, cookie, browser)@j & #j < #i)
          | (cookie = 'null') "

// Proven (3 min)
lemma helper_browser_cookie_matching2[reuse, use_induction, heuristic={helper_browser_cookie_matching2}, hide_lemmas_sources]:
    " All request1 ue as cookie browser #i. BrowserSend(request1, ue, as, cookie, browser)@i
        ==> (Ex request2 old_cookie #j #k. BrowserSend(request2, ue, as, old_cookie, browser)@j
                & AsRecvAuthorizationRequest(as, request2, cookie)@k
                & #j < #k
                & #k < #i)
          | (Ex #j. Rev(as, 'HTTPS')@j)
          | (cookie = 'null') "

define(`hide_lemmas_helpers_browser', `           dnl
      hide_lemma=helper_browser_request_matching  dnl
    , hide_lemma=helper_browser_cookie_matching1  dnl
    , hide_lemma=helper_browser_cookie_matching2  dnl
')

// Proven (< 1 min)
lemma helper_ue_sqn_ordering              dnl
    [ reuse                               dnl
    , use_induction                       dnl
    , heuristic={helper_ue_sqn_ordering}  dnl
    , hide_lemmas_sources                 dnl
    , hide_lemmas_helpers_browser         dnl
    ]:
    " ( All ue sqn1 sqn2 #i #j. UeSqnValueUpdate(ue, sqn1)@i
            & UeSqnValueUpdate(ue, sqn2)@j
            & #i < #j
        ==> (sqn1 << sqn2) ) &
      ( All ue sqn1 sqn2 #i #j. UeSqnValueUpdate(ue, sqn1)@i
            & UeSqnValue(ue, sqn2)@j
            & #i < #j
        ==> (sqn1 << sqn2 | sqn1 = sqn2) ) &
      ( All ue sqn1 sqn2 #i #j. UeSqnValue(ue, sqn1)@i
            & UeSqnValueUpdate(ue, sqn2)@j
            & #i < #j
        ==> (sqn1 << sqn2) ) &
      ( All ue sqn1 sqn2 #i #j. UeSqnValue(ue, sqn1)@i
            & UeSqnValue(ue, sqn2)@j
            & #i < #j
        ==> (sqn1 << sqn2 | sqn1 = sqn2) ) "

// Proven (< 1 min)
lemma helper_ue_sqn_unique              dnl
    [ reuse                             dnl
    , heuristic={helper_ue_sqn_unique}  dnl
    , hide_lemmas_sources               dnl
    , hide_lemmas_helpers_browser       dnl
    ]:
    " All ue sqn #i #j. UeSqnValueUpdate(ue, sqn)@i & UeSqnValueUpdate(ue, sqn)@j
        ==> #i = #j "

define(`hide_lemmas_helpers_sqn', `      dnl
      hide_lemma=helper_ue_sqn_ordering  dnl
    , hide_lemma=helper_ue_sqn_unique    dnl
')

// Proven (6 h 6 min)
lemma helper_secrecy_oauth_state              dnl
    [ reuse                                   dnl
    , heuristic={helper_secrecy_oauth_state}  dnl
    , hide_lemmas_sources                     dnl
    , hide_lemmas_helpers_sqn                 dnl
    ]:
    " All ue as bid session state #i #j. UeAuthReqAs(ue, as, bid, session, state)@i & KU(state)@j
        ==> (Ex key #k. Rev(ue, <'k', key>)@k)
          | (Ex     #k. Rev(as, <'HTTPS' >)@k) "

// --- Executability ---

// Proven (2 h 58 min)
lemma executability_honest                   dnl
    [ heuristic={executability_honest}       dnl
    , hide_lemmas_sources                    dnl
    , hide_lemmas_helpers_sqn                dnl
    , hide_lemma=helper_secrecy_oauth_state  dnl
    ]:
    exists-trace
    " Ex #i. SnRecvSecurityModeComplete()@i
        & not (Ex id data #j. Rev(id, data)@j)
        & (All hn1 hn2 #j #k. HnStart   (hn1)@j & HnStart   (hn2)@k ==> #j = #k)
        & (All ue1 ue2 #j #k. UeStart   (ue1)@j & UeStart   (ue2)@k ==> #j = #k)
        & (All ue1 ue2 #j #k. UePossess (ue1)@j & UePossess (ue2)@k ==> #j = #k) "

// --- Secrecy ---

// Proven (8 min)
lemma secrecy_supi                 dnl
    [ heuristic={secrecy_supi}     dnl
    , hide_lemmas_sources          dnl
    , hide_lemmas_helpers_browser  dnl
    ]:
    " All X supi #i. Secret(X, <'supi', supi>)@i
        ==> not (Ex #j. K(supi)@j)
          | (Ex X Y #j #k.
                Rev(Y, 'channel')@j
              & HnSendAuthConfirm(X, Y)@k
              & Honest(X)@i)
          | (Ex Y    #j. Rev(Y, <'supi',  supi>)@j & Honest(Y)@i)
          | (Ex Y sk #j. Rev(Y, <'sk_hn', sk  >)@j & Honest(Y)@i) "

// Proven (6 h 11 min)
lemma secrecy_supi_sn              dnl
    [ heuristic={secrecy_supi_sn}  dnl
    , hide_lemmas_sources          dnl
    , hide_lemmas_helpers_browser  dnl
    ]:
    " All X supi #i. Secret(X, <'supi_sn', supi>)@i
        ==> not (Ex #j. K(supi)@j)
          | (Ex Y #j.
                Rev(Y, 'channel')@j
              & SnRecvAuthenticationConfirm(Y)@i
              & Honest(Y)@i)
          | (Ex X Y #j #k.
                Rev(Y, 'channel')@j
              & HnSendAuthConfirm(X, Y)@k
              & Honest(X)@i)
          | (Ex Y    #j. Rev(Y, <'supi',  supi>)@j & Honest(Y)@i)
          | (Ex Y sk #j. Rev(Y, <'sk_hn', sk  >)@j & Honest(Y)@i) "

// Proven (22 min)
lemma secrecy_user_id              dnl
    [ heuristic={secrecy_user_id}  dnl
    , hide_lemmas_sources          dnl
    , hide_lemmas_helpers_browser  dnl
    ]:
    " All X user #i. Secret(X, <'user', user>)@i
        ==> not (Ex #j. K(user)@j)
          | (Ex Y client_secret #j. Rev(Y, <'client_secret', client_secret>)@j & Honest(Y)@i)
          | (Ex Y               #j. Rev(Y, <'user',          user         >)@j & Honest(Y)@i)
          | (Ex Y               #j. Rev(Y,  'HTTPS'                        )@j & Honest(Y)@i) "

// Proven (52 min)
lemma secrecy_user_id_pkce              dnl
    [ heuristic={secrecy_user_id_pkce}  dnl
    , hide_lemmas_sources               dnl
    ]:
    " All X user #i. Secret(X, <'user', user>)@i
        ==> not (Ex #j. K(user)@j)
          | (Ex Y ue key #j #k. Rev(ue, <'k', key>)@j
                & UeSendUserCredentials(ue, Y)@k
                & Honest(Y)@i)
          | (Ex Y code_challenge1 code_challenge2 #j.
                PkceCheck(Y, code_challenge1, code_challenge2)@j
              & not (code_challenge1 = code_challenge2)
              & Honest(Y)@i)
          | (Ex Y #j. Rev(Y, <'user', user>)@j & Honest(Y)@i)
          | (Ex Y #j. Rev(Y,  'HTTPS'      )@j & Honest(Y)@i) "

// Proven (4 min)
lemma secrecy_user_password              dnl
    [ heuristic={secrecy_user_password}  dnl
    , hide_lemmas_sources                dnl
    , hide_lemmas_helpers_browser        dnl
    ]:
    " All X password #i. Secret(X, <'password', password>)@i
        ==> not (Ex #j. K(password)@j)
          | (Ex Y #j. Rev(Y, <'password', password>)@j & Honest(Y)@i)
          | (Ex Y #j. Rev(Y,  'HTTPS'              )@j & Honest(Y)@i) "

// Proven (5 min)
lemma secrecy_client_secret              dnl
    [ heuristic={secrecy_client_secret}  dnl
    , hide_lemmas_sources                dnl
    , hide_lemmas_helpers_browser        dnl
    ]:
    " All X client_secret #i. Secret(X, <'client_secret', client_secret>)@i
        ==> not (Ex #j. K(client_secret)@j)
          | (Ex Y #j. Rev(Y, <'client_secret', client_secret>)@j & Honest(Y)@i)
          | (Ex Y #j. Rev(Y,  'HTTPS'                        )@j & Honest(Y)@i) "

// Proven (2 h 22 min)
lemma secrecy_authz_code              dnl
    [ heuristic={secrecy_authz_code}  dnl
    , hide_lemmas_sources             dnl
    ]:
    " All X authz_code #i. Secret(X, <'authz_code', authz_code>)@i
            & AsRecvUserCredentials()@i
        ==> not (Ex #j. K(authz_code)@j)
          | (Ex Y ue key #j #k. Rev(ue, <'k', key>)@j
                & UeSendUserCredentials(ue, Y)@k
                & #k < #i
                & Honest(Y)@i)
          | (Ex Y ue #j #k. Rev(ue, <'authz_code', authz_code>)@j
                & UeSendUserCredentials(ue, Y)@k
                & #k < #i
                & Honest(Y)@i)
          | (Ex Y password #j. Rev(Y, <'password',   password>)@j & Honest(Y)@i)
          | (Ex Y          #j. Rev(Y,  'HTTPS'                )@j & Honest(Y)@i) "

// Proven (6 min)
lemma secrecy_access_token[heuristic={secrecy_access_token}]:
    " All X access_token #i. Secret(X, <'access_token', access_token>)@i
        ==> not (Ex #j. K(access_token)@j)
          | (Ex Y client_secret #j. Rev(Y, <'client_secret', client_secret>)@j & Honest(Y)@i)
          | (Ex Y               #j. Rev(Y,  'HTTPS'                        )@j & Honest(Y)@i) "

// Proven (42 min)
lemma secrecy_access_token_pkce              dnl
    [ heuristic={secrecy_access_token_pkce}  dnl
    , hide_lemmas_sources                    dnl
    ]:
    " All X access_token code_challenge #i. Secret(X, <'access_token', access_token>)@i
            & PkceCheck(X, code_challenge, code_challenge)@i
        ==> not (Ex #j. K(access_token)@j)
          | (Ex Y ue key #j #k. Rev(ue, <'k', key>)@j
                & UeSendUserCredentials(ue, Y)@k
                & #k < #i
                & Honest(Y)@i)
          | (Ex Y password #j. Rev(Y, <'password',   password>)@j & Honest(Y)@i)
          | (Ex Y          #j. Rev(Y,  'HTTPS'                )@j & Honest(Y)@i) "

// Proven (17 min)
lemma secrecy_kseaf                dnl
    [ heuristic={secrecy_kseaf}    dnl
    , hide_lemmas_sources          dnl
    , hide_lemmas_helpers_browser  dnl
    ]:
    " All X k_seaf #i. Secret(X, <'k_seaf', k_seaf>)@i
        ==> not (Ex #j. K(k_seaf)@j)
          | (Ex Y key #j. Rev(Y, <'k', key>)@j & Honest(Y)@i)
          | (Ex Y #j. Rev(Y, 'channel')@j & Honest(Y)@i) "

// --- Weak Agreement ---

// Proven (10 min)
lemma weakagreement_as_user              dnl
    [ heuristic={weakagreement_as_user}  dnl
    , hide_lemmas_sources                dnl
    , hide_lemmas_helpers_browser        dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'as', 'user', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i) "

// Proven (11 h 28 min)
lemma helper_weakagreement_user_as1              dnl
    [ reuse                                      dnl
    , heuristic={helper_weakagreement_user_as1}  dnl
    , hide_lemmas_sources                        dnl
    , hide_lemmas_helpers_browser                dnl
    ]:
    " All ue as authz_code1 authz_code2 rand #i #j.
        UeRecvAuthorizationRedirect(ue, authz_code1, rand)@i
            & HnRecvAccessToken(ue, as, authz_code2, rand)@j
        ==> (authz_code1 = authz_code2)
          | (Ex key #k. Rev(ue, <'k', key>)@k) "

// Proven (1 h 10 min)
lemma helper_weakagreement_user_as2              dnl
    [ reuse                                      dnl
    , heuristic={helper_weakagreement_user_as2}  dnl
    , hide_lemmas_sources                        dnl
    , hide_lemmas_helpers_browser                dnl
    ]:
    " All ue as authz_code rand #i. HnRecvAccessToken(ue, as, authz_code, rand)@i
        ==> (Ex #j. AsSendAccessToken(as, authz_code)@j)
          | (Ex #k. Rev(as, 'HTTPS')@k) "

// Proven (12 h)
lemma weakagreement_user_as              dnl
    [ reuse                              dnl
    , heuristic={weakagreement_user_as}  dnl
    , hide_lemmas_sources                dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'user', 'as', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex s1 s2 Z #j. UeOauthStateCheck(Z, s1, s2)@j
                & not (s1 = s2)
                & Honest(Z)@i)
          | (Ex e1 e2 Z #j. UserEqualCheck(Z, e1, e2)@j
                & not (e1 = e2)
                & Honest(Z)@i)
          | (Ex Z key      #j. Rev(Z, <'k', key            >)@j & Honest(Z)@i)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i)
          | (Ex Z          #j. Rev(Z,   'HTTPS'             )@j & Honest(Z)@i) "

// Proven (not timed)
//
// XXX: The current oracle doesn't work for branches
//
// case user_connect
// > case ue_create
// >> case ue_send_user_credentials_case_4
// >>> case ue_recv_security_mode_command_case_09
// >>> case ue_recv_security_mode_command_case_10
// >>> case ue_recv_security_mode_command_case_11
// >>> case ue_recv_security_mode_command_case_12
//
// which need solve( BrowserState0( ~browser, ~ue, ~request ) @ #vr.3 ) to be
// manually selected as the goal.
lemma weakagreement_user_hn              dnl
    [ heuristic={weakagreement_user_hn}  dnl
    , hide_lemmas_sources                dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'user', 'hn', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex s1 s2 Z #j. UeOauthStateCheck(Z, s1, s2)@j
                & not (s1 = s2)
                & Honest(Z)@i)
          | (Ex e1 e2 Z #j. UserEqualCheck(Z, e1, e2)@j
                & not (e1 = e2)
                & Honest(Z)@i)
          | (Ex Z key      #j. Rev(Z, <'k', key            >)@j & Honest(Z)@i)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i)
          | (Ex Z          #j. Rev(Z,   'HTTPS'             )@j & Honest(Z)@i) "

// Proven (7 min)
lemma weakagreement_as_hn[heuristic={weakagreement_as_hn}]:
    " All X Y t1 #i. Commit(X, Y, <'as', 'hn', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex Z client_secret #j. Rev(Z, <'client_secret', client_secret>)@j & Honest(Z)@i) "

// Proven (1 h 3 min)
lemma weakagreement_hn_as[heuristic={weakagreement_hn_as}]:
    " All X Y t1 #i. Commit(X, Y, <'hn', 'as', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex Z #j. Rev(Z, 'HTTPS')@j & Honest(Z)@i) "

// Proven (1 h 18 min)
lemma weakagreement_hn_user[heuristic={weakagreement_hn_user}]:
    " All X Y t1 #i. Commit(X, Y, <'hn', 'user', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i)
          | (Ex Z          #j. Rev(Z,  'HTTPS'              )@j & Honest(Z)@i) "

// Proven (< 1 min)
lemma weakagreement_sn_hn              dnl
    [ heuristic={weakagreement_sn_hn}  dnl
    , hide_lemmas_sources              dnl
    , hide_lemmas_helpers_browser      dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'sn', 'hn', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex #j. Rev(X, 'channel')@j & Honest(X)@i) "

// Proven (< 1 min)
lemma weakagreement_hn_sn              dnl
    [ heuristic={weakagreement_hn_sn}  dnl
    , hide_lemmas_sources              dnl
    , hide_lemmas_helpers_browser      dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'hn', 'sn', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex #j. Rev(Y, 'channel')@j & Honest(Y)@i) "

// Proven (2 h 26 min)
lemma weakagreement_ue_hn              dnl
    [ heuristic={weakagreement_ue_hn}  dnl
    , hide_lemmas_sources              dnl
    , hide_lemmas_helpers_browser      dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'ue', 'hn', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex key #j. Rev(X, <'k', key>)@j & Honest(X)@i) "

// Proven (5 min)
lemma weakagreement_hn_ue              dnl
    [ heuristic={weakagreement_hn_ue}  dnl
    , hide_lemmas_sources              dnl
    , hide_lemmas_helpers_browser      dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'hn', 'ue', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex key #j. Rev(Y, <'k', key>)@j & Honest(Y)@i) "

// Proven (4 h 16 min)
lemma weakagreement_ue_sn              dnl
    [ heuristic={weakagreement_ue_sn}  dnl
    , hide_lemmas_sources              dnl
    , hide_lemmas_helpers_browser      dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'ue', 'sn', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex Z key #j. Rev(Z, <'k', key>)@j & Honest(Z)@i)
          | (Ex Z     #j. Rev(Z,  'channel')@j & Honest(Z)@i) "

// Proven (3 h 11 min)
lemma weakagreement_sn_ue              dnl
    [ heuristic={weakagreement_sn_ue}  dnl
    , hide_lemmas_sources              dnl
    , hide_lemmas_helpers_browser      dnl
    ]:
    " All X Y t1 #i. Commit(X, Y, <'sn', 'ue', t1>)@i
        ==> (Ex t2 #j. Running(Y, X, t2)@j)
          | (Ex Z key #j. Rev(Z, <'k', key>)@j & Honest(Z)@i)
          | (Ex Z     #j. Rev(Z,  'channel')@j & Honest(Z)@i) "

// --- Non-Injective Agreement ---

// Proven (9 min)
lemma noninjective_agreement_hn_id_as_user              dnl
    [ heuristic={noninjective_agreement_hn_id_as_user}  dnl
    , hide_lemmas_sources                               dnl
    , hide_lemmas_helpers_sqn                           dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'as', 'user', <'hn', t>>)@i
        ==> (Ex #j. Running(Y, X, <'user', 'as', <'hn', t>>)@j)
          | (Ex Z          #j. Rev(Z,  'HTTPS'              )@j & Honest(Z)@i)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i) "

// Proven (1 h 2 min)
lemma noninjective_agreement_as_id_hn_user              dnl
    [ heuristic={noninjective_agreement_as_id_hn_user}  dnl
    , hide_lemmas_sources                               dnl
    , hide_lemmas_helpers_sqn                           dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'hn', 'user', <'as', t>>)@i
        ==> (Ex #j. Running(Y, X, <'user', 'hn', <'as', t>>)@j)
          | (Ex Z          #j. Rev(Z,  'HTTPS'              )@j & Honest(Z)@i)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i) "

// Proven (14 h 41 min)
lemma noninjective_agreement_hn_id_user_as  dnl
    [ heuristic={weakagreement_user_as}     dnl
    , hide_lemmas_sources                   dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'user', 'as', <'hn', t>>)@i
        ==> (Ex #j. Running(Y, X, <'as', 'user', <'hn', t>>)@j)
          | (Ex s1 s2 Z #j. UeOauthStateCheck(Z, s1, s2)@j
                & not (s1 = s2)
                & Honest(Z)@i)
          | (Ex e1 e2 Z #j. UserEqualCheck(Z, e1, e2)@j
                & not (e1 = e2)
                & Honest(Z)@i)
          | (Ex Z key      #j. Rev(Z, <'k', key            >)@j & Honest(Z)@i)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i)
          | (Ex Z          #j. Rev(Z,   'HTTPS'             )@j & Honest(Z)@i) "

// Proven (not timed)
lemma noninjective_agreement_as_id_user_hn              dnl
    [ heuristic={noninjective_agreement_as_id_user_hn}  dnl
    , hide_lemmas_sources                               dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'user', 'hn', <'as', t>>)@i
        ==> (Ex #j. Running(Y, X, <'hn', 'user', <'as', t>>)@j)
          | (Ex s1 s2 Z #j. UeOauthStateCheck(Z, s1, s2)@j
                & not (s1 = s2)
                & Honest(Z)@i)
          | (Ex e1 e2 Z #j. UserEqualCheck(Z, e1, e2)@j
                & not (e1 = e2)
                & Honest(Z)@i)
          | (Ex Z key      #j. Rev(Z, <'k', key            >)@j & Honest(Z)@i)
          | (Ex Z password #j. Rev(Z, <'password', password>)@j & Honest(Z)@i)
          | (Ex Z          #j. Rev(Z,   'HTTPS'             )@j & Honest(Z)@i) "

// Proven (44 min)
lemma noninjective_agreement_user_id_hn_as              dnl
    [ heuristic={noninjective_agreement_user_id_hn_as}  dnl
    , hide_lemmas_sources                               dnl
    , hide_lemmas_helpers_browser                       dnl
    , hide_lemmas_helpers_sqn                           dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'hn', 'as', <'user', t>>)@i
        ==> (Ex #j. Running(Y, X, <'as', 'hn', <'user', t>>)@j)
          | (Ex Z #j. Rev(Z, 'HTTPS')@j & Honest(Z)@i) "

// Proven (4 h 50 min)
lemma noninjective_agreement_sn_id_ue_hn              dnl
    [ heuristic={noninjective_agreement_sn_id_ue_hn}  dnl
    , hide_lemmas_sources                             dnl
    , hide_lemmas_helpers_browser                     dnl
    , hide_lemmas_helpers_sqn                         dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'ue', 'hn', <'sn', t>>)@i
        ==> (Ex #j. Running(Y, X, <'hn', 'ue', <'sn', t>>)@j)
          | (Ex Z #j. Rev(Z, 'channel')@j & Honest(Z)@i)
          | (Ex key #j. Rev(X, <'k', key>)@j & Honest(X)@i) "

// Proven (2 min)
lemma noninjective_agreement_sn_id_hn_ue              dnl
    [ heuristic={noninjective_agreement_sn_id_hn_ue}  dnl
    , hide_lemmas_sources                             dnl
    , hide_lemmas_helpers_browser                     dnl
    , hide_lemmas_helpers_sqn                         dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'hn', 'ue', <'sn', t>>)@i
        ==> (Ex #j. Running(Y, X, <'ue', 'hn', <'sn', t>>)@j)
          | (Ex #j. Rev(t, 'channel')@j & Honest(t)@i)
          | (Ex key #j. Rev(Y, <'k', key>)@j & Honest(Y)@i) "

// Proven (< 1 min)
lemma noninjective_agreement_supi_sn_hn              dnl
    [ heuristic={noninjective_agreement_supi_sn_hn}  dnl
    , hide_lemmas_sources                            dnl
    , hide_lemmas_helpers_browser                    dnl
    , hide_lemmas_helpers_sqn                        dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'sn', 'hn', <'ue', t>>)@i
        ==> (Ex #j. Running(Y, X, <'hn', 'sn', <'ue', t>>)@j)
          | (Ex #j. Rev(X, 'channel')@j & Honest(X)@i) "

// --- Injective Agreement ---

// Proven (49 min)
lemma injective_agreement_access_token_hn_as[heuristic={injective_agreement_access_token_hn_as}, hide_lemmas_sources]:
    " All X Y t #i. Commit(X, Y, <'hn', 'as', <'access_token', t>>)@i
        ==> (Ex #j. Running(Y, X, <'as', 'hn', <'access_token', t>>)@j
                & not (Ex P Q #k. Commit(P, Q, <'hn', 'as', <'access_token', t>>)@k & not (#k = #i)))
          | (Ex Z #j. Rev(Z, 'HTTPS')@j & Honest(Z)@i) "

// Proven (25 h 33 min)
lemma injective_agreement_k_seaf_ue_hn                       dnl
    [ heuristic={injective_agreement_k_seaf_ue_hn}           dnl
    , hide_lemmas_sources                                    dnl
    , hide_lemmas_helpers_browser                            dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'ue', 'hn', <'k_seaf', t>>)@i
        ==> (Ex #j. Running(Y, X, <'hn', 'ue', <'k_seaf', t>>)@j
                & not (Ex P Q #k. Commit(P, Q, <'ue', 'hn', <'k_seaf', t>>)@k & not (#k = #i)))
          | (Ex key #j. Rev(X, <'k', key>)@j & Honest(X)@i) "

// Proven (2 h 28 min)
lemma injective_agreement_k_seaf_hn_ue                       dnl
    [ heuristic={injective_agreement_k_seaf_hn_ue}           dnl
    , hide_lemmas_sources                                    dnl
    , hide_lemmas_helpers_browser                            dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'hn', 'ue', <'k_seaf', t>>)@i
        ==> (Ex #j. Running(Y, X, <'ue', 'hn', <'k_seaf', t>>)@j
                & not (Ex P Q #k. Commit(P, Q, <'hn', 'ue', <'k_seaf', t>>)@k & not (#k = #i)))
          | (Ex key #j. Rev(Y, <'k', key>)@j & Honest(Y)@i) "

// Proven (2 h 55 min)
lemma injective_agreement_k_seaf_sn_hn                       dnl
    [ heuristic={injective_agreement_k_seaf_sn_hn}           dnl
    , hide_lemmas_sources                                    dnl
    , hide_lemmas_helpers_browser                            dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'sn', 'hn', <'k_seaf', t>>)@i
        ==> (Ex #j. Running(Y, X, <'hn', 'sn', <'k_seaf', t>>)@j
                & not (Ex P Q #k. Commit(P, Q, <'sn', 'hn', <'k_seaf', t>>)@k & not (#k = #i)))
          | (Ex Z ue key #j #k. Rev(ue, <'k', key>)@j
                & HnSendAuthReq(Z, ue)@k
                & #k < #i
                & Honest(Z)@i)
          | (Ex #j. Rev(X, 'channel')@j & Honest(X)@i) "

// Proven (4 min)
lemma helper_injective_agreement_k_seaf_ue_sn              dnl
    [ reuse                                                dnl
    , heuristic={helper_injective_agreement_k_seaf_ue_sn}  dnl
    , hide_lemmas_sources                                  dnl
    , hide_lemmas_helpers_browser                          dnl
    ]:
    " All X Y P Q t #i #k. Commit(X, Y, <'ue', 'sn', <'k_seaf', t>>)@i
            & Commit(P, Q, <'ue', 'sn', <'k_seaf', t>>)@k
        ==> (#i = #k)
          | (Ex Z key #j. Rev(Z, <'k', key>)@j & Honest(Z)@i)
          | (Ex Z     #j. Rev(Z,  'channel')@j & Honest(Z)@i) "

// Proven (9 h 43 min)
lemma injective_agreement_k_seaf_ue_sn                       dnl
    [ heuristic={injective_agreement_k_seaf_ue_sn}           dnl
    , hide_lemmas_sources                                    dnl
    , hide_lemmas_helpers_browser                            dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'ue', 'sn', <'k_seaf', t>>)@i
        ==> (Ex #j. Running(Y, X, <'sn', 'ue', <'k_seaf', t>>)@j
                & not (Ex P Q #k. Commit(P, Q, <'ue', 'sn', <'k_seaf', t>>)@k & not (#k = #i)))
          | (Ex Z key #j. Rev(Z, <'k', key>)@j & Honest(Z)@i)
          | (Ex Z     #j. Rev(Z,  'channel')@j & Honest(Z)@i) "

// Proven (34 min)
lemma helper_injective_agreement_k_seaf_sn_ue              dnl
    [ reuse                                                dnl
    , heuristic={helper_injective_agreement_k_seaf_sn_ue}  dnl
    , hide_lemmas_sources                                  dnl
    , hide_lemmas_helpers_browser                          dnl
    ]:
    " All X Y P Q t #i #k. Commit(X, Y, <'sn', 'ue', <'k_seaf', t>>)@i
            & Commit(P, Q, <'sn', 'ue', <'k_seaf', t>>)@k
        ==> (#i = #k)
          | (Ex Z key #j. Rev(Z, <'k', key>)@j & Honest(Z)@i)
          | (Ex Z     #j. Rev(Z,  'channel')@j & Honest(Z)@i) "

// Proven (3 h 34 min)
lemma injective_agreement_k_seaf_sn_ue                       dnl
    [ heuristic={injective_agreement_k_seaf_sn_ue}           dnl
    , hide_lemmas_sources                                    dnl
    , hide_lemmas_helpers_browser                            dnl
    ]:
    " All X Y t #i. Commit(X, Y, <'sn', 'ue', <'k_seaf', t>>)@i
        ==> (Ex #j. Running(Y, X, <'ue', 'sn', <'k_seaf', t>>)@j
                & not (Ex P Q #k. Commit(P, Q, <'sn', 'ue', <'k_seaf', t>>)@k & not (#k = #i)))
          | (Ex Z key #j. Rev(Z, <'k', key>)@j & Honest(Z)@i)
          | (Ex Z     #j. Rev(Z,  'channel')@j & Honest(Z)@i) "

end
