// Offline WAV/PCM runner. stdout carries only keyword events.
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#ifndef FEATURES_ONLY
#include "tensorflow/lite/c/c_api.h"
#endif

struct MwwFrontend;
extern "C" MwwFrontend *mww_frontend_create();
extern "C" void mww_frontend_destroy(MwwFrontend *);
extern "C" int mww_frontend_process(MwwFrontend *, const int16_t *, size_t, uint16_t *, size_t);
using File = std::unique_ptr<FILE, decltype(&fclose)>;
using Frontend = std::unique_ptr<MwwFrontend, decltype(&mww_frontend_destroy)>;
using Clock = std::chrono::steady_clock;
static int64_t ns(Clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-t).count();
}
static void require(bool value, const char *reason) {
    if (!value) throw std::runtime_error(reason);
}
static uint16_t le16(const uint8_t *b) { return b[0] | (unsigned(b[1]) << 8); }
static uint32_t le32(const uint8_t *b) { return le16(b) | (uint32_t(le16(b+2)) << 16); }
static void exact(FILE *f, void *p, size_t n) { require(fread(p,1,n,f)==n,"short input"); }
static void write_all(FILE *f, const void *p, size_t n) {
    require(fwrite(p,1,n,f)==n,"trace write");
}

// Validate the whole RIFF container before making any events observable.
static uint32_t wave(FILE *f) {
    require(fseek(f,0,SEEK_END)==0,"seek");
    long length=ftell(f);
    require(length>=12 && length<=256L*1024*1024,"WAV size");
    rewind(f);
    uint8_t h[16];
    exact(f,h,12);
    require(!memcmp(h,"RIFF",4) && !memcmp(h+8,"WAVE",4) && le32(h+4)==uint32_t(length-8),"RIFF");
    bool fmt=false;
    long data=-1;
    uint32_t bytes=0;
    while(ftell(f)<length) {
        exact(f,h,8);
        uint32_t n=le32(h+4);
        long offset=ftell(f);
        uint64_t end=uint64_t(offset)+n+(n&1);
        require(end<=uint64_t(length),"chunk extent");
        if (!memcmp(h,"fmt ",4)) {
            require(!fmt && n>=16,"format chunk");
            exact(f,h,16);
            require(le16(h)==1 && le16(h+2)==1 && le32(h+4)==16000 &&
                    le32(h+8)==32000 && le16(h+12)==2 && le16(h+14)==16,"expected mono PCM16LE 16 kHz");
            fmt=true;
        } else if (!memcmp(h,"data",4)) {
            require(fmt && data<0 && n && !(n&1),"data chunk");
            bytes=n; data=offset;
        }
        require(fseek(f,long(end),SEEK_SET)==0,"chunk seek");
    }
    require(data>=0 && fseek(f,data,SEEK_SET)==0,"missing data");
    return bytes;
}

static int8_t quant(uint16_t x) {
    return int8_t(std::min(127, (int(x)*256+333)/666-128));
}
struct Decision {
    std::array<uint8_t,10> scores{};
    unsigned pos=0, grace=74, sum=0;
    bool advance(int raw) {
        if (raw>=0) {
            sum-=scores[pos]; scores[pos]=uint8_t(raw); sum+=scores[pos];
            pos=(pos+1)%scores.size();
        }
        if(grace) --grace;
        return !grace && sum>2295;
    }
};

#ifndef FEATURES_ONLY
using Model = std::unique_ptr<TfLiteModel,decltype(&TfLiteModelDelete)>;
using Options = std::unique_ptr<TfLiteInterpreterOptions,decltype(&TfLiteInterpreterOptionsDelete)>;
using Interpreter = std::unique_ptr<TfLiteInterpreter,decltype(&TfLiteInterpreterDelete)>;
static Interpreter interpreter(const TfLiteModel *model) {
    Options o(TfLiteInterpreterOptionsCreate(),TfLiteInterpreterOptionsDelete);
    require(bool(o),"options"); TfLiteInterpreterOptionsSetNumThreads(o.get(),1);
    Interpreter i(TfLiteInterpreterCreate(model,o.get()),TfLiteInterpreterDelete);
    require(i && TfLiteInterpreterAllocateTensors(i.get())==kTfLiteOk,"allocate");
    require(TfLiteInterpreterGetInputTensorCount(i.get())==1 && TfLiteInterpreterGetOutputTensorCount(i.get())==1,"arity");
    auto in=TfLiteInterpreterGetInputTensor(i.get(),0);
    auto out=TfLiteInterpreterGetOutputTensor(i.get(),0);
    require(in && TfLiteTensorType(in)==kTfLiteInt8 && TfLiteTensorNumDims(in)==3 &&
            TfLiteTensorDim(in,0)==1 && TfLiteTensorDim(in,1)==3 && TfLiteTensorDim(in,2)==40 &&
            TfLiteTensorByteSize(in)==120,"input metadata");
    require(out && TfLiteTensorType(out)==kTfLiteUInt8 && TfLiteTensorNumDims(out)==2 &&
            TfLiteTensorDim(out,0)==1 && TfLiteTensorDim(out,1)==1 && TfLiteTensorByteSize(out)==1,"output metadata");
    auto q=TfLiteTensorQuantizationParams(out);
    require(q.scale==1.0f/256 && q.zero_point==0,"output quantization");
    return i;
}
using ModelPtr = const TfLiteModel *;
#else
using ModelPtr = const void *;
#endif

// CLI: runner MODEL TRACE_OR_- CHUNK_SAMPLES WAV... ; use - for continuous PCM stdin.
static void session(ModelPtr model, FILE *source, bool raw, FILE *trace, unsigned chunk) {
    uint64_t remaining=raw?0:wave(source);
    auto start=Clock::now();
    Frontend fe(mww_frontend_create(),mww_frontend_destroy);
    require(bool(fe),"frontend");
    auto fe_init=ns(start);
    auto init=Clock::now();
#ifndef FEATURES_ONLY
    auto it=interpreter(model);
#else
    (void)model;
#endif
    auto model_init=ns(init);
    uint64_t samples=0, frames=0, invokes=0, dsp_ns=0, invoke_ns=0;
    std::array<int16_t,160> block{};
    std::array<int8_t,120> group{};
    unsigned fill=0, rows=0;
    Decision d;
    std::vector<uint8_t> input(chunk*2);
    while(raw || remaining) {
        size_t ask=raw?input.size():size_t(std::min<uint64_t>(input.size(),remaining));
        size_t count=fread(input.data(),1,ask,source);
        require(!ferror(source) && (raw || count==ask) && !(count&1),"PCM read");
        if(!count) break;
        if(!raw) remaining-=count;
        for(size_t j=0;j<count;j+=2) {
            block[fill++]=int16_t(le16(&input[j])); ++samples;
            if(fill!=160) continue;
            fill=0;
            std::array<uint16_t,40> feature{};
            auto before=Clock::now();
            int n=mww_frontend_process(fe.get(),block.data(),160,feature.data(),40);
            dsp_ns+=ns(before);
            if(!n) continue;
            require(n==40,"feature count");
            auto dest=group.begin()+40*rows;
            std::transform(feature.begin(),feature.end(),dest,quant);
            ++frames; ++rows;
            int16_t score=-1;
            if(trace) {write_all(trace,feature.data(),80); write_all(trace,&*dest,40);}
            if(rows==3) {
                rows=0;
#ifndef FEATURES_ONLY
                auto begin=Clock::now();
                uint8_t value;
                require(TfLiteTensorCopyFromBuffer(TfLiteInterpreterGetInputTensor(it.get(),0),group.data(),120)==kTfLiteOk &&
                        TfLiteInterpreterInvoke(it.get())==kTfLiteOk &&
                        TfLiteTensorCopyToBuffer(TfLiteInterpreterGetOutputTensor(it.get(),0),&value,1)==kTfLiteOk,"inference");
                invoke_ns+=ns(begin); ++invokes; score=value;
#endif
            }
            bool detected=d.advance(score);
            if(trace) {
                uint16_t sum=uint16_t(d.sum);
                uint8_t event=detected;
                write_all(trace,&score,2); write_all(trace,&sum,2); write_all(trace,&event,1);
            }
            if(detected) {
                require(puts("Алиса")>=0 && fflush(stdout)==0,"event write");
                fe.reset(mww_frontend_create()); require(bool(fe),"frontend restart");
#ifndef FEATURES_ONLY
                it=interpreter(model);
#endif
                rows=0; d=Decision{};
            }
        }
    }
    require(samples>0,"empty PCM");
    fprintf(stderr,"metrics %llu %llu %llu %llu %llu %llu %llu %llu\n",
            (unsigned long long)samples,(unsigned long long)frames,(unsigned long long)invokes,
            (unsigned long long)fe_init,(unsigned long long)model_init,(unsigned long long)dsp_ns,
            (unsigned long long)invoke_ns,(unsigned long long)ns(start));
}
int main(int argc,char **argv) {
    try {
        if(argc==2 && !strcmp(argv[1],"--quant-table")) {
            for(unsigned i=0;i<=65535;++i) {int8_t v=quant(i); write_all(stdout,&v,1);}
            return fflush(stdout)!=0;
        }
        if(argc==2 && !strcmp(argv[1],"--decision-trace")) {
            Decision d; int c;
            while((c=getchar())!=EOF) {
                bool hit=d.advance(c);
                printf("%u %u\n",d.sum,unsigned(hit)); if(hit) d=Decision{};
            }
            return ferror(stdin) || fflush(stdout);
        }
        require(argc>=5,"usage: runner MODEL TRACE|- CHUNK_SAMPLES WAV|- ...");
        char *end=nullptr; unsigned long chunk=strtoul(argv[3],&end,10);
        require(end!=argv[3] && !*end && chunk>=1 && chunk<=8192,"chunk");
        File trace(nullptr,fclose);
        if(strcmp(argv[2],"-")) {trace.reset(fopen(argv[2],"wb")); require(bool(trace),"trace open");}
#ifndef FEATURES_ONLY
        require(!strcmp(TfLiteVersion(),"2.17.1"),"runtime version");
        Model model(TfLiteModelCreateFromFile(argv[1]),TfLiteModelDelete);
        require(bool(model),"model");
        ModelPtr m=model.get();
#else
        ModelPtr m=nullptr;
#endif
        for(int i=4;i<argc;++i) {
            bool raw=!strcmp(argv[i],"-");
            File f(raw?nullptr:fopen(argv[i],"rb"),fclose);
            require(raw || f,"WAV open");
            session(m,raw?stdin:f.get(),raw,trace.get(),unsigned(chunk));
        }
        if(trace) require(fflush(trace.get())==0,"trace flush");
        return 0;
    } catch(const std::exception &e) {fprintf(stderr,"FAIL %s\n",e.what()); return 1;}
}
