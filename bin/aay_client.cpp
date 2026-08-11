#include "aay_auth.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
void save_sk(const AAYKeyPair&kp,const std::string&p){
    std::ofstream f(p,std::ios::binary);f.write((char*)kp.rho,32);f.write((char*)kp.sigma,32);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++)f.write((char*)&kp.s[i][j],2);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++)f.write((char*)&kp.t[i][j],2);}
bool load_sk(AAYKeyPair&kp,const std::string&p){
    std::ifstream f(p,std::ios::binary);if(!f)return false;
    f.read((char*)kp.rho,32);f.read((char*)kp.sigma,32);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++){int16_t v;f.read((char*)&v,2);kp.s[i][j]=v;}
    for(int i=0;i<K;i++)for(int j=0;j<N;j++){int16_t v;f.read((char*)&v,2);kp.t[i][j]=v;}
    return(bool)f;}
int conn_proxy(const std::string&host,uint16_t port){
    struct addrinfo hints={},*res;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    char ps[8];snprintf(ps,sizeof(ps),"%d",port);
    if(getaddrinfo(host.c_str(),ps,&hints,&res)!=0)return -1;
    int fd=socket(res->ai_family,res->ai_socktype,0);
    if(connect(fd,res->ai_addr,res->ai_addrlen)<0){close(fd);freeaddrinfo(res);return -1;}
    freeaddrinfo(res);return fd;}
bool do_handshake_client(int fd,const std::string&id,const AAYKeyPair&kp,std::array<uint8_t,32>&sk){
    auto pk=serialize_pk(kp.rho,kp.t);
    std::vector<uint8_t>hello(64+PK_SIZE,0);
    size_t il=std::min(id.size(),(size_t)63);memcpy(hello.data(),id.c_str(),il);
    memcpy(hello.data()+64,pk.data(),PK_SIZE);
    auto f=make_frame(MSG_HELLO,hello.data(),hello.size());
    send(fd,f.data(),f.size(),MSG_NOSIGNAL);
    fprintf(stderr,"[CLIENT] HELLO terkirim '%s'\n",id.c_str());
    MsgType type;std::vector<uint8_t>payload;
    if(!read_frame(fd,type,payload)){fprintf(stderr,"[CLIENT] Read gagal\n");return false;}
    if(type==MSG_AUTH_FAIL){payload.push_back(0);fprintf(stderr,"[CLIENT] AUTH_FAIL: %s\n",(char*)payload.data());return false;}
    if(type!=MSG_CHALLENGE||payload.size()!=32+PK_SIZE){fprintf(stderr,"[CLIENT] CHALLENGE invalid\n");return false;}
    uint8_t ch[32];memcpy(ch,payload.data(),32);
    const uint8_t*spk=payload.data()+32;
    auto spkh=h256(std::vector<uint8_t>(spk,spk+PK_SIZE));
    fprintf(stderr,"[CLIENT] Server PK: %02x%02x%02x%02x...\n",spkh[0],spkh[1],spkh[2],spkh[3]);
    uint8_t sr[32];PolyVec st;deserialize_pk(spk,sr,st);
    auto er=aay_encap(sr,st);
    auto rf=make_frame(MSG_RESPONSE,er.ct.data(),er.ct.size());
    send(fd,rf.data(),rf.size(),MSG_NOSIGNAL);
    fprintf(stderr,"[CLIENT] RESPONSE terkirim\n");
    if(!read_frame(fd,type,payload)){fprintf(stderr,"[CLIENT] Read AUTH_OK gagal\n");return false;}
    if(type==MSG_AUTH_FAIL){payload.push_back(0);fprintf(stderr,"[CLIENT] AUTH_FAIL: %s\n",(char*)payload.data());return false;}
    if(type!=MSG_AUTH_OK||payload.size()!=CT_SIZE){fprintf(stderr,"[CLIENT] AUTH_OK invalid\n");return false;}
    auto k2=aay_decap(kp.s,kp.rho,kp.t,payload.data());
    sk=derive_session_key(er.key,k2,ch);
    fprintf(stderr,"[CLIENT] session_key: %02x%02x%02x%02x...\n",sk[0],sk[1],sk[2],sk[3]);
    fprintf(stderr,"[CLIENT] === MUTUAL AUTH SUKSES ===\n");
    return true;}
void stdin_sock(int fd,std::atomic<bool>&run){
    uint8_t buf[4096];while(run.load()){ssize_t n=read(STDIN_FILENO,buf,sizeof(buf));if(n<=0){run=false;break;}size_t s=0;while(s<(size_t)n){ssize_t r=send(fd,buf+s,n-s,MSG_NOSIGNAL);if(r<=0){run=false;return;}s+=r;}}}
void sock_stdout(int fd,std::atomic<bool>&run){
    uint8_t buf[4096];while(run.load()){ssize_t n=recv(fd,buf,sizeof(buf),0);if(n<=0){run=false;break;}fwrite(buf,1,n,stdout);fflush(stdout);}}
int main(int argc,char*argv[]){
    if(argc<2){
        fprintf(stderr,"Usage:\n  ./aay_client register <id> <sk.bin>\n  ./aay_client test <host> <port> <id> <sk.bin>\n  ./aay_client tunnel <host> <port> <id> <sk.bin>\n");return 1;}
    std::string mode=argv[1];
    if(mode=="register"&&argc>=4){
        fprintf(stderr,"=== Register '%s' ===\n",argv[2]);
        auto kp=aay_keygen();save_sk(kp,argv[3]);
        fprintf(stderr,"sk tersimpan: %s\n\n",argv[3]);
        auto pk=serialize_pk(kp.rho,kp.t);
        fprintf(stdout,"%s ",argv[2]);for(uint8_t b:pk)fprintf(stdout,"%02x",b);fprintf(stdout,"\n");
        fprintf(stderr,"[OK] Tambahkan baris di atas ke clients.db di server\n");}
    else if((mode=="test"||mode=="tunnel")&&argc>=6){
        AAYKeyPair kp;if(!load_sk(kp,argv[5])){fprintf(stderr,"Gagal load sk: %s\n",argv[5]);return 1;}
        int fd=conn_proxy(argv[2],(uint16_t)atoi(argv[3]));
        if(fd<0){fprintf(stderr,"Gagal koneksi ke %s:%s\n",argv[2],argv[3]);return 1;}
        std::array<uint8_t,32>sk;
        if(!do_handshake_client(fd,argv[4],kp,sk)){close(fd);return 1;}
        if(mode=="test"){fprintf(stderr,"[OK] Test selesai.\n");close(fd);}
        else{std::atomic<bool>run{true};std::thread t1(stdin_sock,fd,std::ref(run));std::thread t2(sock_stdout,fd,std::ref(run));t1.join();t2.join();close(fd);}}
    else{fprintf(stderr,"Argumen tidak valid.\n");return 1;}
    return 0;}
