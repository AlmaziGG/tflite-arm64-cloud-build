// Inspect only initialized integer coefficients from the upstream bridge.
#include <cstdio>
#include "frontend_bridge.cc"
int main() {
    auto *f=mww_frontend_create();
    if (!f) return 1;
    const auto &s=f->state;
    for (size_t i=0;i<s.window.size;++i)
        std::printf("window %zu %d\n",i,s.window.coefficients[i]);
    const auto &b=s.filterbank;
    for (int c=0;c<=b.num_channels;++c) {
        printf("frequency_start %d %d\n",c,b.channel_frequency_starts[c]);
        for (int j=0;j<b.channel_widths[c];++j) {
            int i=b.channel_weight_starts[c]+j;
            printf("weight %d %d\nunweight %d %d\n",i,b.weights[i],i,b.unweights[i]);
        }
    }
    const auto *lut=s.pcan_gain_control.gain_lut;
    printf("pcan 0 %d\npcan 1 %d\n",lut[0],lut[1]);
    for (int k=2;k<=kWideDynamicFunctionBits;++k) {
        for (int j=0;j<3;++j) {
            int i=4*k-6+j;
            printf("pcan %d %d\n",i,lut[i]);
        }
    }
    mww_frontend_destroy(f);
    return std::fflush(stdout)!=0;
}
