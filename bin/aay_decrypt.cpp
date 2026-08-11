#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>
static constexpr int N=256,Q=3329,K=3,ETA=2,DU=10,DV=4;
using Poly=std::array<int16_t,N>;
using PolyVec=std::array<Poly,K>;
using PolyMat=std::array<PolyVec,K>;
inline int16_t mod_q(int32_t x){int16_t r=x%Q;return r<0?r+Q:r;}
Poly poly_add(const Poly&a,const Poly&b){Poly r;for(int i=0;i<N;i++)r[i]=mod_q(a[i]+b[i]);return r;}
Poly poly_sub(const Poly&a,const Poly&b){Poly r;for(int i=0;i<N;i++)r[i]=mod_q(a[i]-b[i]);return r;}
Poly poly_mul(const Poly&a,const Poly&b){
    std::array<int32_t,N>r={};
    for(int i=0;i<N;i++)for(int j=0;j<N;j++){int idx=i+j;if(idx<N)r[idx]+=(int32_t)a[i]*b[j];else r[idx-N]-=(int32_t)a[i]*b[j];}
    Poly o;for(int i=0;i<N;i++)o[i]=mod_q(r[i]);return o;}
std::vector<uint8_t> shake128(const uint8_t*in,size_t il,size_t ol){
    std::vector<uint8_t>o(ol);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_shake128(),nullptr);EVP_DigestUpdate(c,in,il);
    EVP_DigestFinalXOF(c,o.data(),ol);EVP_MD_CTX_free(c);return o;}
std::vector<uint8_t> shake256(const uint8_t*in,size_t il,size_t ol){
    std::vector<uint8_t>o(ol);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_shake256(),nullptr);EVP_DigestUpdate(c,in,il);
    EVP_DigestFinalXOF(c,o.data(),ol);EVP_MD_CTX_free(c);return o;}
std::vector<uint8_t> sha3_512(const std::vector<uint8_t>&in){
    std::vector<uint8_t>o(64);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_sha3_512(),nullptr);EVP_DigestUpdate(c,in.data(),in.size());
    unsigned int l=64;EVP_DigestFinal_ex(c,o.data(),&l);EVP_MD_CTX_free(c);return o;}
std::vector<uint8_t> sha3_256(const std::vector<uint8_t>&in){
    std::vector<uint8_t>o(32);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_sha3_256(),nullptr);EVP_DigestUpdate(c,in.data(),in.size());
    unsigned int l=32;EVP_DigestFinal_ex(c,o.data(),&l);EVP_MD_CTX_free(c);return o;}
Poly sample_uniform(const uint8_t*rho,uint8_t ni,uint8_t nj){
    uint8_t s[34];memcpy(s,rho,32);s[32]=ni;s[33]=nj;
    auto x=shake128(s,34,3*N*2);Poly p;int cnt=0;
    for(size_t i=0;i+1<x.size()&&cnt<N;i+=2){uint16_t v=(uint16_t)x[i]|((uint16_t)(x[i+1]&0x0F)<<8);if(v<Q)p[cnt++]=(int16_t)v;}
    while(cnt<N)p[cnt++]=0;return p;}
Poly sample_cbd(const uint8_t*sigma,uint8_t nonce){
    uint8_t s[33];memcpy(s,sigma,32);s[32]=nonce;
    auto b=shake256(s,33,ETA*N/4);Poly p;
    for(int i=0;i<N;i++){uint8_t byte=b[i/2];if(i%2==0)byte&=0x0F;else byte>>=4;
        int a=((byte>>0)&1)+((byte>>1)&1),bb=((byte>>2)&1)+((byte>>3)&1);p[i]=mod_q(a-bb);}
    return p;}
int16_t compress_c(int16_t x,int d){return(int16_t)(((int32_t)x*(1<<d)+Q/2)/Q&((1<<d)-1));}
int16_t decompress_c(int16_t x,int d){return(int16_t)(((int32_t)x*Q+(1<<(d-1)))/(1<<d));}
Poly compress_p(const Poly&p,int d){Poly o;for(int i=0;i<N;i++)o[i]=compress_c(p[i],d);return o;}
Poly decompress_p(const Poly&p,int d){Poly o;for(int i=0;i<N;i++)o[i]=decompress_c(p[i],d);return o;}
Poly unpack_du(const uint8_t*b){Poly p;for(int i=0;i<N;i++)p[i]=(int16_t)((uint16_t)b[i*2]|((uint16_t)b[i*2+1]<<8)&0x3FF);return p;}
Poly unpack_dv(const uint8_t*b){Poly p;for(int i=0;i<N;i+=2){uint8_t v=b[i/2];p[i]=v&0x0F;p[i+1]=(v>>4)&0x0F;}return p;}
std::array<uint8_t,32> decode_msg(const Poly&m){
    std::array<uint8_t,32>msg={};
    for(int b=0;b<256&&b<N;b++){int16_t c=m[b],d=c-Q/2;if(d<0)d=-d;if(d<Q/4)msg[b/8]|=(1<<(b%8));}
    return msg;}
bool ct_cmp(const std::vector<uint8_t>&a,const std::vector<uint8_t>&b){
    if(a.size()!=b.size())return false;uint8_t d=0;for(size_t i=0;i<a.size();i++)d|=a[i]^b[i];return d==0;}
struct SK{uint8_t sigma[32];PolyVec s;};
struct PK{uint8_t rho[32];PolyVec t;};
struct Rec{std::vector<uint8_t>ct_kem,ct_aes;uint8_t nonce[12];};
Poly read_poly(std::ifstream&f){Poly p;for(int i=0;i<N;i++){int16_t v;f.read((char*)&v,2);p[i]=v;}return p;}
PolyVec read_pv(std::ifstream&f){PolyVec pv;for(int i=0;i<K;i++)pv[i]=read_poly(f);return pv;}
SK load_sk(const std::string&p){std::ifstream f(p,std::ios::binary);
    if(!f){fprintf(stderr,"[ERR] %s\n",p.c_str());exit(1);}
    SK sk;f.read((char*)sk.sigma,32);sk.s=read_pv(f);return sk;}
PK load_pk(const std::string&p){std::ifstream f(p,std::ios::binary);
    if(!f){fprintf(stderr,"[ERR] %s\n",p.c_str());exit(1);}
    PK pk;f.read((char*)pk.rho,32);pk.t=read_pv(f);return pk;}
Rec load_rec(const std::string&p){std::ifstream f(p,std::ios::binary);
    if(!f){fprintf(stderr,"[ERR] %s\n",p.c_str());exit(1);}
    Rec r;uint32_t kl;f.read((char*)&kl,4);r.ct_kem.resize(kl);f.read((char*)r.ct_kem.data(),kl);
    f.read((char*)r.nonce,12);uint32_t al;f.read((char*)&al,4);r.ct_aes.resize(al);
    f.read((char*)r.ct_aes.data(),al);return r;}
std::vector<uint8_t> aes_dec(const uint8_t*k,const uint8_t*n,const uint8_t*ct,size_t cl){
    if(cl<16){fprintf(stderr,"[ERR] ct pendek\n");return{};}
    size_t dl=cl-16;const uint8_t*tag=ct+dl;
    EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);
    EVP_DecryptInit_ex(c,nullptr,nullptr,k,n);
    std::vector<uint8_t>pt(dl);int len=0;
    EVP_DecryptUpdate(c,pt.data(),&len,ct,(int)dl);
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,(void*)tag);
    int ret=EVP_DecryptFinal_ex(c,pt.data()+len,&len);
    EVP_CIPHER_CTX_free(c);
    if(ret<=0){fprintf(stderr,"[ERR] GCM auth GAGAL!\n");return{};}
    return pt;}
int main(int argc,char*argv[]){
    if(argc<4){fprintf(stderr,"Usage: ./aay_decrypt sk.bin pk.bin record.bin\n");return 1;}
    printf("=== ARSF-31071602 Decrypt ===\n");
    SK sk=load_sk(argv[1]);PK pk=load_pk(argv[2]);Rec rec=load_rec(argv[3]);
    printf("[ct_kem] %zu B  [ct_aes] %zu B\n\n",rec.ct_kem.size(),rec.ct_aes.size());
    size_t us=K*N*2;
    PolyVec u;for(int i=0;i<K;i++)u[i]=decompress_p(unpack_du(rec.ct_kem.data()+i*N*2),DU);
    Poly v=decompress_p(unpack_dv(rec.ct_kem.data()+us),DV);
    Poly su={};for(int i=0;i<K;i++)su=poly_add(su,poly_mul(sk.s[i],u[i]));
    auto m=decode_msg(poly_sub(v,su));
    std::vector<uint8_t>pki(pk.rho,pk.rho+32);
    for(int i=0;i<4;i++){pki.push_back(pk.t[0][i]&0xFF);pki.push_back((pk.t[0][i]>>8)&0xFF);}
    auto pkh=sha3_256(pki);
    std::vector<uint8_t>Gi(m.begin(),m.end());Gi.insert(Gi.end(),pkh.begin(),pkh.end());
    auto Go=sha3_512(Gi);
    uint8_t Kr[32],rs[32];memcpy(Kr,Go.data(),32);memcpy(rs,Go.data()+32,32);
    PolyVec r,e1;Poly e2;
    for(int i=0;i<K;i++){r[i]=sample_cbd(rs,i);e1[i]=sample_cbd(rs,K+i);}
    e2=sample_cbd(rs,2*K);
    PolyMat A;for(int i=0;i<K;i++)for(int j=0;j<K;j++)A[i][j]=sample_uniform(pk.rho,i,j);
    PolyVec uc;
    for(int j=0;j<K;j++){Poly cs={};for(int i=0;i<K;i++)cs=poly_add(cs,poly_mul(A[i][j],r[i]));uc[j]=poly_add(cs,e1[j]);}
    Poly vc=e2;for(int i=0;i<K;i++)vc=poly_add(vc,poly_mul(pk.t[i],r[i]));
    for(int b=0;b<256&&b<N;b++){int bv=(m[b/8]>>(b%8))&1;vc[b]=mod_q(vc[b]+bv*(Q/2));}
    std::vector<uint8_t>ctc;
    for(int i=0;i<K;i++){auto cp=compress_p(uc[i],DU);for(int j=0;j<N;j++){uint16_t v=cp[j]&0x3FF;ctc.push_back(v&0xFF);ctc.push_back(v>>8);}}
    {auto cp=compress_p(vc,DV);for(int i=0;i<N;i+=2)ctc.push_back((cp[i]&0x0F)|((cp[i+1]&0x0F)<<4));}
    if(!ct_cmp(rec.ct_kem,ctc)){fprintf(stderr,"[WARN] FO GAGAL — implicit rejection!\n");return 1;}
    printf("[FO]  CT valid.\n");
    std::vector<uint8_t>kdf(Kr,Kr+32);kdf.insert(kdf.end(),m.begin(),m.end());
    auto Kf=shake256(kdf.data(),kdf.size(),32);
    auto pt=aes_dec(Kf.data(),rec.nonce,rec.ct_aes.data(),rec.ct_aes.size());
    if(pt.empty())return 1;
    printf("\n[OK] Plaintext (%zu bytes):\n",pt.size());
    printf("──────────────────────────────\n");
    fwrite(pt.data(),1,pt.size(),stdout);
    printf("\n──────────────────────────────\n");
    return 0;}
