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
Poly compress_p(const Poly&p,int d){Poly o;for(int i=0;i<N;i++)o[i]=compress_c(p[i],d);return o;}
void pack_du(const Poly&p,std::vector<uint8_t>&b){for(int i=0;i<N;i++){uint16_t v=p[i]&0x3FF;b.push_back(v&0xFF);b.push_back(v>>8);}}
void pack_dv(const Poly&p,std::vector<uint8_t>&b){for(int i=0;i<N;i+=2)b.push_back((p[i]&0x0F)|((p[i+1]&0x0F)<<4));}
struct PK{uint8_t rho[32];PolyVec t;};
Poly read_poly(std::ifstream&f){Poly p;for(int i=0;i<N;i++){int16_t v;f.read((char*)&v,2);p[i]=v;}return p;}
PolyVec read_pv(std::ifstream&f){PolyVec pv;for(int i=0;i<K;i++)pv[i]=read_poly(f);return pv;}
PK load_pk(const std::string&path){std::ifstream f(path,std::ios::binary);
    if(!f){fprintf(stderr,"[ERR] %s\n",path.c_str());exit(1);}
    PK pk;f.read((char*)pk.rho,32);pk.t=read_pv(f);return pk;}
struct AESOut{std::vector<uint8_t>ct,nonce;};
AESOut aes_enc(const uint8_t*k,const uint8_t*pt,size_t pl){
    AESOut r;r.nonce.resize(12);RAND_bytes(r.nonce.data(),12);
    EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);
    EVP_EncryptInit_ex(c,nullptr,nullptr,k,r.nonce.data());
    r.ct.resize(pl+16);int len=0;
    EVP_EncryptUpdate(c,r.ct.data(),&len,pt,(int)pl);int tot=len;
    EVP_EncryptFinal_ex(c,r.ct.data()+tot,&len);tot+=len;
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,r.ct.data()+tot);
    r.ct.resize(tot+16);EVP_CIPHER_CTX_free(c);return r;}
int main(int argc,char*argv[]){
    if(argc<4){fprintf(stderr,"Usage: ./aay_encrypt pk.bin \"plaintext\" out.bin\n");return 1;}
    printf("=== ARSF-31071602 Encrypt ===\n");
    PK pk=load_pk(argv[1]);
    std::vector<uint8_t>pt;
    std::string pa=argv[2];
    if(pa[0]=='@'){std::ifstream f(pa.substr(1),std::ios::binary);pt.assign(std::istreambuf_iterator<char>(f),{});}
    else pt.assign(pa.begin(),pa.end());
    printf("[IN] plaintext: %zu bytes\n\n",pt.size());
    uint8_t m[32];RAND_bytes(m,32);
    std::vector<uint8_t>pki(pk.rho,pk.rho+32);
    for(int i=0;i<4;i++){pki.push_back(pk.t[0][i]&0xFF);pki.push_back((pk.t[0][i]>>8)&0xFF);}
    auto pkh=sha3_256(pki);
    std::vector<uint8_t>Gi(m,m+32);Gi.insert(Gi.end(),pkh.begin(),pkh.end());
    auto Go=sha3_512(Gi);
    uint8_t Kr[32],rs[32];memcpy(Kr,Go.data(),32);memcpy(rs,Go.data()+32,32);
    PolyVec r,e1;Poly e2;
    for(int i=0;i<K;i++){r[i]=sample_cbd(rs,i);e1[i]=sample_cbd(rs,K+i);}
    e2=sample_cbd(rs,2*K);
    PolyMat A;for(int i=0;i<K;i++)for(int j=0;j<K;j++)A[i][j]=sample_uniform(pk.rho,i,j);
    PolyVec u;
    for(int j=0;j<K;j++){Poly cs={};for(int i=0;i<K;i++)cs=poly_add(cs,poly_mul(A[i][j],r[i]));u[j]=poly_add(cs,e1[j]);}
    Poly v=e2;for(int i=0;i<K;i++)v=poly_add(v,poly_mul(pk.t[i],r[i]));
    for(int b=0;b<256&&b<N;b++){int bv=(m[b/8]>>(b%8))&1;v[b]=mod_q(v[b]+bv*(Q/2));}
    std::vector<uint8_t>ct_kem;
    for(int i=0;i<K;i++)pack_du(compress_p(u[i],DU),ct_kem);
    pack_dv(compress_p(v,DV),ct_kem);
    std::vector<uint8_t>kdf(Kr,Kr+32);kdf.insert(kdf.end(),m,m+32);
    auto Kf=shake256(kdf.data(),kdf.size(),32);
    auto aes=aes_enc(Kf.data(),pt.data(),pt.size());
    printf("[KEM] ct_kem: %zu bytes\n[AES] ct_aes: %zu bytes\n",ct_kem.size(),aes.ct.size());
    std::ofstream f(argv[3],std::ios::binary);
    uint32_t kl=ct_kem.size();f.write((char*)&kl,4);f.write((char*)ct_kem.data(),kl);
    f.write((char*)aes.nonce.data(),12);
    uint32_t al=aes.ct.size();f.write((char*)&al,4);f.write((char*)aes.ct.data(),al);
    printf("[OUT] %s (%zu bytes)\n[OK]\n",argv[3],(size_t)(4+kl+12+4+al));return 0;}
