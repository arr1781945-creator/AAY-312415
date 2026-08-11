#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
static constexpr int N=256,Q=3329,K=3,ETA=2,DU=10,DV=4;
using Poly=std::array<int16_t,N>;
using PolyVec=std::array<Poly,K>;
using PolyMat=std::array<PolyVec,K>;
static constexpr size_t PK_SIZE=32+K*N*2;
static constexpr size_t CT_SIZE=K*N*2+N/2;
enum MsgType:uint8_t{MSG_HELLO=0x01,MSG_CHALLENGE=0x02,MSG_RESPONSE=0x03,MSG_AUTH_OK=0x04,MSG_AUTH_FAIL=0x05,MSG_DATA=0x06};
inline std::vector<uint8_t> make_frame(MsgType t,const uint8_t*p,size_t l){
    std::vector<uint8_t>f(4+l);f[0]=(uint8_t)t;f[1]=0;f[2]=(uint8_t)(l>>8);f[3]=(uint8_t)(l&0xFF);
    if(l&&p)memcpy(f.data()+4,p,l);return f;}
inline bool read_frame(int fd,MsgType&type,std::vector<uint8_t>&payload){
    uint8_t hdr[4];size_t got=0;ssize_t n;
    while(got<4){n=recv(fd,hdr+got,4-got,0);if(n<=0)return false;got+=n;}
    type=(MsgType)hdr[0];uint16_t len=((uint16_t)hdr[2]<<8)|hdr[3];
    payload.resize(len);got=0;
    while(got<len){n=recv(fd,payload.data()+got,len-got,0);if(n<=0)return false;got+=n;}
    return true;}
inline int16_t mod_q(int32_t x){int16_t r=(int16_t)(x%Q);return r<0?r+Q:r;}
inline Poly poly_add(const Poly&a,const Poly&b){Poly r;for(int i=0;i<N;i++)r[i]=mod_q(a[i]+b[i]);return r;}
inline Poly poly_sub(const Poly&a,const Poly&b){Poly r;for(int i=0;i<N;i++)r[i]=mod_q(a[i]-b[i]);return r;}
inline Poly poly_mul(const Poly&a,const Poly&b){
    std::array<int32_t,N>r={};
    for(int i=0;i<N;i++)for(int j=0;j<N;j++){int idx=i+j;if(idx<N)r[idx]+=(int32_t)a[i]*b[j];else r[idx-N]-=(int32_t)a[i]*b[j];}
    Poly o;for(int i=0;i<N;i++)o[i]=mod_q(r[i]);return o;}
inline std::vector<uint8_t> xof128(const uint8_t*in,size_t il,size_t ol){
    std::vector<uint8_t>o(ol);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_shake128(),nullptr);EVP_DigestUpdate(c,in,il);
    EVP_DigestFinalXOF(c,o.data(),ol);EVP_MD_CTX_free(c);return o;}
inline std::vector<uint8_t> xof256(const uint8_t*in,size_t il,size_t ol){
    std::vector<uint8_t>o(ol);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_shake256(),nullptr);EVP_DigestUpdate(c,in,il);
    EVP_DigestFinalXOF(c,o.data(),ol);EVP_MD_CTX_free(c);return o;}
inline std::vector<uint8_t> h512(const std::vector<uint8_t>&in){
    std::vector<uint8_t>o(64);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_sha3_512(),nullptr);EVP_DigestUpdate(c,in.data(),in.size());
    unsigned int l=64;EVP_DigestFinal_ex(c,o.data(),&l);EVP_MD_CTX_free(c);return o;}
inline std::vector<uint8_t> h256(const std::vector<uint8_t>&in){
    std::vector<uint8_t>o(32);EVP_MD_CTX*c=EVP_MD_CTX_new();
    EVP_DigestInit_ex(c,EVP_sha3_256(),nullptr);EVP_DigestUpdate(c,in.data(),in.size());
    unsigned int l=32;EVP_DigestFinal_ex(c,o.data(),&l);EVP_MD_CTX_free(c);return o;}
inline Poly sample_uniform(const uint8_t*rho,uint8_t ni,uint8_t nj){
    uint8_t s[34];memcpy(s,rho,32);s[32]=ni;s[33]=nj;
    auto x=xof128(s,34,3*N*2);Poly p;int cnt=0;
    for(size_t i=0;i+1<x.size()&&cnt<N;i+=2){uint16_t v=(uint16_t)x[i]|((uint16_t)(x[i+1]&0x0F)<<8);if(v<Q)p[cnt++]=(int16_t)v;}
    while(cnt<N)p[cnt++]=0;return p;}
inline Poly sample_cbd(const uint8_t*sigma,uint8_t nonce){
    uint8_t s[33];memcpy(s,sigma,32);s[32]=nonce;
    auto b=xof256(s,33,ETA*N/4);Poly p;
    for(int i=0;i<N;i++){uint8_t byte=b[i/2];if(i%2==0)byte&=0x0F;else byte>>=4;
        int a=((byte>>0)&1)+((byte>>1)&1),bb=((byte>>2)&1)+((byte>>3)&1);p[i]=mod_q(a-bb);}
    return p;}
inline int16_t cmp(int16_t x,int d){return(int16_t)(((int32_t)x*(1<<d)+Q/2)/Q&((1<<d)-1));}
inline int16_t dcmp(int16_t x,int d){return(int16_t)(((int32_t)x*Q+(1<<(d-1)))/(1<<d));}
inline Poly compress(const Poly&p,int d){Poly o;for(int i=0;i<N;i++)o[i]=cmp(p[i],d);return o;}
inline Poly decompress(const Poly&p,int d){Poly o;for(int i=0;i<N;i++)o[i]=dcmp(p[i],d);return o;}
inline std::vector<uint8_t> serialize_pk(const uint8_t*rho,const PolyVec&t){
    std::vector<uint8_t>out(PK_SIZE);memcpy(out.data(),rho,32);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++){out[32+i*N*2+j*2]=(uint8_t)(t[i][j]&0xFF);out[32+i*N*2+j*2+1]=(uint8_t)(t[i][j]>>8);}
    return out;}
inline void deserialize_pk(const uint8_t*buf,uint8_t*rho,PolyVec&t){
    memcpy(rho,buf,32);
    for(int i=0;i<K;i++)for(int j=0;j<N;j++)t[i][j]=(int16_t)((uint16_t)buf[32+i*N*2+j*2]|((uint16_t)buf[32+i*N*2+j*2+1]<<8));}
struct AAYKeyPair{uint8_t rho[32],sigma[32];PolyVec t,s;};
inline AAYKeyPair aay_keygen(){
    AAYKeyPair kp;RAND_bytes(kp.rho,32);RAND_bytes(kp.sigma,32);
    PolyMat A;for(int i=0;i<K;i++)for(int j=0;j<K;j++)A[i][j]=sample_uniform(kp.rho,i,j);
    PolyVec s,e;for(int i=0;i<K;i++){s[i]=sample_cbd(kp.sigma,i);e[i]=sample_cbd(kp.sigma,K+i);}
    kp.s=s;
    for(int i=0;i<K;i++){Poly rs={};for(int j=0;j<K;j++)rs=poly_add(rs,poly_mul(A[i][j],s[j]));kp.t[i]=poly_add(rs,e[i]);}
    return kp;}
struct EncapResult{std::vector<uint8_t>ct;std::array<uint8_t,32>key;};
inline EncapResult aay_encap(const uint8_t*pr,const PolyVec&pt){
    uint8_t m[32];RAND_bytes(m,32);
    std::vector<uint8_t>pki(pr,pr+32);
    for(int i=0;i<4;i++){pki.push_back(pt[0][i]&0xFF);pki.push_back((pt[0][i]>>8)&0xFF);}
    auto pkh=h256(pki);
    std::vector<uint8_t>Gi(m,m+32);Gi.insert(Gi.end(),pkh.begin(),pkh.end());
    auto Go=h512(Gi);uint8_t Kr[32],rs[32];memcpy(Kr,Go.data(),32);memcpy(rs,Go.data()+32,32);
    PolyVec r,e1;Poly e2;
    for(int i=0;i<K;i++){r[i]=sample_cbd(rs,i);e1[i]=sample_cbd(rs,K+i);}e2=sample_cbd(rs,2*K);
    PolyMat A;for(int i=0;i<K;i++)for(int j=0;j<K;j++)A[i][j]=sample_uniform(pr,i,j);
    PolyVec u;
    for(int j=0;j<K;j++){Poly cs={};for(int i=0;i<K;i++)cs=poly_add(cs,poly_mul(A[i][j],r[i]));u[j]=poly_add(cs,e1[j]);}
    Poly v=e2;for(int i=0;i<K;i++)v=poly_add(v,poly_mul(pt[i],r[i]));
    for(int b=0;b<256&&b<N;b++){int bv=(m[b/8]>>(b%8))&1;v[b]=mod_q(v[b]+bv*(Q/2));}
    std::vector<uint8_t>ct(CT_SIZE);
    for(int i=0;i<K;i++){auto uc=compress(u[i],DU);for(int j=0;j<N;j++){uint16_t val=(uint16_t)(uc[j]&0x3FF);ct[i*N*2+j*2]=val&0xFF;ct[i*N*2+j*2+1]=val>>8;}}
    auto vc=compress(v,DV);size_t base=K*N*2;
    for(int i=0;i<N;i+=2)ct[base+i/2]=(uint8_t)((vc[i]&0x0F)|((vc[i+1]&0x0F)<<4));
    EncapResult res;res.ct=ct;
    std::vector<uint8_t>kdf(Kr,Kr+32);kdf.insert(kdf.end(),m,m+32);
    auto Kf=xof256(kdf.data(),kdf.size(),32);memcpy(res.key.data(),Kf.data(),32);
    return res;}
inline std::array<uint8_t,32> aay_decap(const PolyVec&ss,const uint8_t*or_,const PolyVec&ot,const uint8_t*cb){
    PolyVec u;Poly v;
    for(int i=0;i<K;i++)for(int j=0;j<N;j++)u[i][j]=(int16_t)((uint16_t)cb[i*N*2+j*2]|((uint16_t)cb[i*N*2+j*2+1]<<8)&0x3FF);
    size_t base=K*N*2;for(int i=0;i<N;i+=2){uint8_t b=cb[base+i/2];v[i]=b&0x0F;v[i+1]=(b>>4)&0x0F;}
    for(int i=0;i<K;i++)u[i]=decompress(u[i],DU);v=decompress(v,DV);
    Poly su={};for(int i=0;i<K;i++)su=poly_add(su,poly_mul(ss[i],u[i]));
    Poly mp=poly_sub(v,su);
    std::array<uint8_t,32>mb={};
    for(int b=0;b<256&&b<N;b++){int16_t c=mp[b],d=c-Q/2;if(d<0)d=-d;if(d<Q/4)mb[b/8]|=(1<<(b%8));}
    std::vector<uint8_t>pki(or_,or_+32);
    for(int i=0;i<4;i++){pki.push_back(ot[0][i]&0xFF);pki.push_back((ot[0][i]>>8)&0xFF);}
    auto pkh=h256(pki);
    std::vector<uint8_t>Gi(mb.begin(),mb.end());Gi.insert(Gi.end(),pkh.begin(),pkh.end());
    auto Go=h512(Gi);uint8_t Kr[32];memcpy(Kr,Go.data(),32);
    std::vector<uint8_t>kdf(Kr,Kr+32);kdf.insert(kdf.end(),mb.begin(),mb.end());
    auto Kf=xof256(kdf.data(),kdf.size(),32);
    std::array<uint8_t,32>key;memcpy(key.data(),Kf.data(),32);return key;}
inline std::array<uint8_t,32> derive_session_key(const std::array<uint8_t,32>&k1,const std::array<uint8_t,32>&k2,const uint8_t*ch){
    std::vector<uint8_t>kdf;kdf.insert(kdf.end(),k1.begin(),k1.end());kdf.insert(kdf.end(),k2.begin(),k2.end());kdf.insert(kdf.end(),ch,ch+32);
    auto o=xof256(kdf.data(),kdf.size(),32);std::array<uint8_t,32>key;memcpy(key.data(),o.data(),32);return key;}
inline bool ct_eq(const uint8_t*a,const uint8_t*b,size_t l){uint8_t d=0;for(size_t i=0;i<l;i++)d|=a[i]^b[i];return d==0;}
