#include "aay_auth.hpp"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <csignal>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
struct Config{uint16_t listen_port=5433;std::string pg_host="127.0.0.1";uint16_t pg_port=5432;std::string sk_path="server_sk.bin";std::string clients_db="clients.db";int max_conn=64;int hs_timeout_ms=5000;};
struct ServerState{AAYKeyPair keypair;std::vector<uint8_t>pk_bytes;std::unordered_map<std::string,std::vector<uint8_t>>auth_clients;std::unordered_map<std::string,std::chrono::steady_clock::time_point>blacklist;std::mutex bl_mutex;std::atomic<int>active{0};};
static ServerState g;static std::atomic<bool>running{true};
#define LOGI(fmt,...) fprintf(stderr,"[INFO] " fmt "\n",##__VA_ARGS__)
#define LOGW(fmt,...) fprintf(stderr,"[WARN] " fmt "\n",##__VA_ARGS__)
#define LOGE(fmt,...) fprintf(stderr,"[ERR ] " fmt "\n",##__VA_ARGS__)
void save_kp(const AAYKeyPair&kp,const std::string&p){
    std::ofstream f(p,std::ios::binary);f.write((char*)kp.rho,32);f.write((char*)kp.sigma,32);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++)f.write((char*)&kp.t[i][j],2);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++)f.write((char*)&kp.s[i][j],2);}
bool load_kp(AAYKeyPair&kp,const std::string&p){
    std::ifstream f(p,std::ios::binary);if(!f)return false;
    f.read((char*)kp.rho,32);f.read((char*)kp.sigma,32);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++){int16_t v;f.read((char*)&v,2);kp.t[i][j]=v;}
    for(int i=0;i<K;i++)for(int j=0;j<N;j++){int16_t v;f.read((char*)&v,2);kp.s[i][j]=v;}
    return(bool)f;}
void load_clients(const std::string&path){
    std::ifstream f(path);if(!f){LOGW("clients.db tidak ada");return;}
    std::string id,pk_hex;int cnt=0;
    while(f>>id>>pk_hex){
        if(pk_hex.size()!=PK_SIZE*2){LOGW("Skip %s: pk_hex salah",id.c_str());continue;}
        std::vector<uint8_t>pk(PK_SIZE);
        for(size_t i=0;i<PK_SIZE;i++){unsigned int b;sscanf(pk_hex.c_str()+i*2,"%02x",&b);pk[i]=(uint8_t)b;}
        g.auth_clients[id]=pk;cnt++;}
    LOGI("Loaded %d authorized clients",cnt);}
bool is_bl(const std::string&ip){
    std::lock_guard<std::mutex>lk(g.bl_mutex);auto it=g.blacklist.find(ip);
    if(it==g.blacklist.end())return false;
    if(std::chrono::steady_clock::now()>it->second){g.blacklist.erase(it);return false;}return true;}
void bl_ip(const std::string&ip,int s=60){
    std::lock_guard<std::mutex>lk(g.bl_mutex);
    g.blacklist[ip]=std::chrono::steady_clock::now()+std::chrono::seconds(s);
    LOGW("Blacklist %s %ds",ip.c_str(),s);}
bool send_all(int fd,const uint8_t*buf,size_t len){
    size_t s=0;while(s<len){ssize_t n=send(fd,buf+s,len-s,MSG_NOSIGNAL);if(n<=0)return false;s+=n;}return true;}
bool send_frame(int fd,MsgType t,const uint8_t*p,size_t l){auto f=make_frame(t,p,l);return send_all(fd,f.data(),f.size());}
int conn_pg(const std::string&host,uint16_t port){
    struct addrinfo hints={},*res;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    char ps[8];snprintf(ps,sizeof(ps),"%d",port);
    if(getaddrinfo(host.c_str(),ps,&hints,&res)!=0)return -1;
    int fd=socket(res->ai_family,res->ai_socktype,0);
    if(connect(fd,res->ai_addr,res->ai_addrlen)<0){close(fd);freeaddrinfo(res);return -1;}
    freeaddrinfo(res);return fd;}
void tunnel(int cfd,int pfd,const std::string&ip){
    uint8_t buf[65536];struct pollfd fds[2];
    fds[0]={cfd,POLLIN,0};fds[1]={pfd,POLLIN,0};
    while(running.load()){
        int r=poll(fds,2,1000);if(r<0)break;if(r==0)continue;
        if(fds[0].revents&POLLIN){ssize_t n=recv(cfd,buf,sizeof(buf),0);if(n<=0)break;if(!send_all(pfd,buf,n))break;}
        if(fds[1].revents&POLLIN){ssize_t n=recv(pfd,buf,sizeof(buf),0);if(n<=0)break;if(!send_all(cfd,buf,n))break;}
        if(fds[0].revents&(POLLHUP|POLLERR))break;if(fds[1].revents&(POLLHUP|POLLERR))break;}
    LOGI("[%s] Tunnel selesai",ip.c_str());}
bool do_handshake(int cfd,const std::string&ip,std::array<uint8_t,32>&sk){
    MsgType type;std::vector<uint8_t>payload;
    if(!read_frame(cfd,type,payload)||type!=MSG_HELLO||payload.size()!=64+PK_SIZE){
        LOGW("[%s] HELLO invalid",ip.c_str());return false;}
    char cid[65]={};memcpy(cid,payload.data(),64);
    const uint8_t*cpk=payload.data()+64;
    LOGI("[%s] HELLO dari '%s'",ip.c_str(),cid);
    auto it=g.auth_clients.find(std::string(cid));
    if(it==g.auth_clients.end()){
        const char*r="client_id tidak diotorisasi";send_frame(cfd,MSG_AUTH_FAIL,(const uint8_t*)r,strlen(r));
        LOGW("[%s] '%s' tidak diotorisasi",ip.c_str(),cid);return false;}
    if(!ct_eq(cpk,it->second.data(),PK_SIZE)){
        const char*r="pk mismatch";send_frame(cfd,MSG_AUTH_FAIL,(const uint8_t*)r,strlen(r));
        LOGW("[%s] PK mismatch",ip.c_str());return false;}
    uint8_t ch[32];RAND_bytes(ch,32);
    std::vector<uint8_t>chp(32+PK_SIZE);memcpy(chp.data(),ch,32);memcpy(chp.data()+32,g.pk_bytes.data(),PK_SIZE);
    if(!send_frame(cfd,MSG_CHALLENGE,chp.data(),chp.size()))return false;
    LOGI("[%s] CHALLENGE dikirim",ip.c_str());
    if(!read_frame(cfd,type,payload)||type!=MSG_RESPONSE||payload.size()!=CT_SIZE){
        LOGW("[%s] RESPONSE invalid",ip.c_str());return false;}
    auto k1=aay_decap(g.keypair.s,g.keypair.rho,g.keypair.t,payload.data());
    LOGI("[%s] Decap OK",ip.c_str());
    uint8_t cr[32];PolyVec ct;deserialize_pk(cpk,cr,ct);
    auto er=aay_encap(cr,ct);
    if(!send_frame(cfd,MSG_AUTH_OK,er.ct.data(),er.ct.size()))return false;
    LOGI("[%s] AUTH_OK — mutual auth selesai",ip.c_str());
    sk=derive_session_key(k1,er.key,ch);
    LOGI("[%s] session_key: %02x%02x%02x%02x...",ip.c_str(),sk[0],sk[1],sk[2],sk[3]);
    return true;}
void handle_conn(int cfd,std::string ip,Config cfg){
    g.active++;LOGI("[%s] Koneksi baru (total:%d)",ip.c_str(),(int)g.active);
    struct timeval tv{cfg.hs_timeout_ms/1000,(cfg.hs_timeout_ms%1000)*1000};
    setsockopt(cfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    std::array<uint8_t,32>sk={};bool ok=false;
    try{ok=do_handshake(cfd,ip,sk);}catch(...){}
    if(!ok){LOGW("[%s] Auth GAGAL",ip.c_str());bl_ip(ip);close(cfd);g.active--;return;}
    tv={0,0};setsockopt(cfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    int pfd=conn_pg(cfg.pg_host,cfg.pg_port);
    if(pfd<0){LOGE("[%s] Gagal koneksi PG",ip.c_str());close(cfd);g.active--;return;}
    LOGI("[%s] Tunnel aktif",ip.c_str());
    tunnel(cfd,pfd,ip);close(pfd);close(cfd);g.active--;
    LOGI("[%s] Selesai (total:%d)",ip.c_str(),(int)g.active);}
void sig_h(int){running=false;}
int main(int argc,char*argv[]){
    Config cfg;
    if(argc>=2)cfg.listen_port=(uint16_t)atoi(argv[1]);
    if(argc>=3)cfg.pg_host=argv[2];
    if(argc>=4)cfg.pg_port=(uint16_t)atoi(argv[3]);
    if(argc>=5)cfg.sk_path=argv[4];
    if(argc>=6)cfg.clients_db=argv[5];
    signal(SIGINT,sig_h);signal(SIGTERM,sig_h);signal(SIGPIPE,SIG_IGN);
    if(!load_kp(g.keypair,cfg.sk_path)){
        LOGI("Generate server keypair baru...");g.keypair=aay_keygen();save_kp(g.keypair,cfg.sk_path);
        LOGI("Tersimpan di %s",cfg.sk_path.c_str());}
    else LOGI("Keypair dimuat: %s",cfg.sk_path.c_str());
    g.pk_bytes=serialize_pk(g.keypair.rho,g.keypair.t);
    auto fp=h256(g.pk_bytes);
    LOGI("Server PK: %02x%02x%02x%02x%02x%02x%02x%02x...",fp[0],fp[1],fp[2],fp[3],fp[4],fp[5],fp[6],fp[7]);
    load_clients(cfg.clients_db);
    int srv=socket(AF_INET,SOCK_STREAM,0);int opt=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in addr={};addr.sin_family=AF_INET;addr.sin_addr.s_addr=INADDR_ANY;addr.sin_port=htons(cfg.listen_port);
    if(bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0){LOGE("Bind gagal port %d",cfg.listen_port);return 1;}
    listen(srv,cfg.max_conn);
    LOGI("=== AAY-312415 PQC Proxy ===");
    LOGI("Listen  : 0.0.0.0:%d",cfg.listen_port);
    LOGI("Forward : %s:%d",cfg.pg_host.c_str(),cfg.pg_port);
    while(running.load()){
        struct sockaddr_in ca={};socklen_t al=sizeof(ca);
        int cfd=accept(srv,(struct sockaddr*)&ca,&al);
        if(cfd<0){if(running.load())LOGE("accept error");continue;}
        std::string ip=inet_ntoa(ca.sin_addr);
        if(is_bl(ip)){LOGW("[%s] Blacklisted",ip.c_str());close(cfd);continue;}
        if(g.active>=cfg.max_conn){LOGW("[%s] Max conn",ip.c_str());close(cfd);continue;}
        std::thread(handle_conn,cfd,ip,cfg).detach();}
    close(srv);LOGI("Shutdown.");return 0;}
