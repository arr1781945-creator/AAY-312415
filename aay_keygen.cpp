#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>
static constexpr int N=256,Q=3329,K=3,ETA=2;
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
struct KeyPair{uint8_t rho[32],sigma[32];PolyVec t,s;};
KeyPair aay_keygen(){
    KeyPair kp;RAND_bytes(kp.rho,32);RAND_bytes(kp.sigma,32);
    PolyMat A;for(int i=0;i<K;i++)for(int j=0;j<K;j++)A[i][j]=sample_uniform(kp.rho,i,j);
    PolyVec s,e;for(int i=0;i<K;i++){s[i]=sample_cbd(kp.sigma,i);e[i]=sample_cbd(kp.sigma,K+i);}
    kp.s=s;
    for(int i=0;i<K;i++){Poly rs={};for(int j=0;j<K;j++)rs=poly_add(rs,poly_mul(A[i][j],s[j]));kp.t[i]=poly_add(rs,e[i]);}
    return kp;}
void write_poly(std::ofstream&f,const Poly&p){for(int i=0;i<N;i++)f.write((const char*)&p[i],2);}
void write_pv(std::ofstream&f,const PolyVec&pv){for(int i=0;i<K;i++)write_poly(f,pv[i]);}
int main(){
    printf("=== AAY-312415 KeyGen ===\nN=%d Q=%d K=%d eta=%d\n\n",N,Q,K,ETA);
    auto kp=aay_keygen();
    {std::ofstream f("pk.bin",std::ios::binary);f.write((const char*)kp.rho,32);write_pv(f,kp.t);printf("[pk] pk.bin  (%d bytes)\n",32+K*N*2);}
    {std::ofstream f("sk.bin",std::ios::binary);f.write((const char*)kp.sigma,32);write_pv(f,kp.s);printf("[sk] sk.bin  (%d bytes)\n",32+K*N*2);}
    printf("\n[rho] ");for(int i=0;i<8;i++)printf("%02x",kp.rho[i]);printf("...\n");
    printf("[t0]  ");for(int i=0;i<4;i++)printf("%d ",kp.t[0][i]);printf("...\n");
    printf("[s0]  ");for(int i=0;i<4;i++)printf("%d ",kp.s[0][i]);printf("...\n");
    printf("\n[OK] Selesai. Jaga sk.bin!\n");return 0;}
