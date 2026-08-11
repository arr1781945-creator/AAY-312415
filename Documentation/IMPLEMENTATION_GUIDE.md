# Implementation Guide

## Building

```bash
g++ -std=c++17 -O2 -c src/arsf_31071602_ntt.cpp -I include/
g++ -O2 -o app app.cpp arsf_31071602_ntt.o -I include/
API
namespace ARSF {
  class NTT {
  public:
    using Poly = std::array<uint32_t, 1024>;
    
    static void ntt(Poly& a);
    static void intt(Poly& a);
    static void mul(Poly& result, const Poly& a, const Poly& b);
    static uint32_t barrett_reduce(uint64_t x);
  };
}
Example
#include "arsf_31071602_ntt.hpp"

int main() {
    NTT::Poly a, b, result;
    a[0] = 1; a[1] = 2;
    b[0] = 1; b[1] = 3;
    NTT::mul(result, a, b);
    // result = [1, 5, 6, ...]
    return 0;
}
