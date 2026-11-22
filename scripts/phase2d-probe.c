#define _GNU_SOURCE
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <time.h>
#include "tensorflow/lite/core/c/c_api_experimental.h"

static unsigned completed;
static void require(int ok, const char *stage) {
    if (!ok) { fprintf(stderr,"FAIL %s %u\n",stage,completed); exit(1); }
}
static uint64_t now(void) {
    struct timespec ts;
    require(clock_gettime(CLOCK_MONOTONIC,&ts)==0,"clock");
    return (uint64_t)ts.tv_sec*1000000000+ts.tv_nsec;
}
static void checkpoint(const char *stage,unsigned index) {
    struct mallinfo2 m=mallinfo2();
    printf("point %s %u %zu %zu\n",stage,index,m.uordblks,m.hblkhd);
    fflush(stdout);
    require(getchar()=='\n',"checkpoint");
}
static TfLiteInterpreter *create(TfLiteModel *model) {
    TfLiteInterpreterOptions *options=TfLiteInterpreterOptionsCreate();
    require(options!=NULL,"options");
    TfLiteInterpreterOptionsSetNumThreads(options,1);
    TfLiteInterpreter *it=TfLiteInterpreterCreate(model,options);
    TfLiteInterpreterOptionsDelete(options);
    require(it!=NULL,"create");
    return it;
}
static void allocate(TfLiteInterpreter *it) {
    require(TfLiteInterpreterAllocateTensors(it)==kTfLiteOk,"allocate");
}
static void features(unsigned batch,int8_t *dst) {
    for (unsigned frame=0;frame<3;++frame) {
        unsigned f=(batch%256)*3+frame;
        uint32_t seed=12345u+f;
        for (unsigned bin=0;bin<40;++bin) {
            seed=1664525u*seed+1013904223u;
            int vals[]={0,-128,32,-32,bin%2 ? 64:-64,(int)(seed>>24)-128};
            dst[40*frame+bin]=vals[batch%256<64 ? 0 : batch%256<128 ? 2 : (batch%256)%6];
        }
    }
}
struct sample {uint64_t copy,invoke,read,total; uint8_t value;};
static struct sample step(TfLiteInterpreter *it,unsigned index) {
    uint64_t start=now();
    int8_t buf[120]; features(index,buf);
    TfLiteTensor *in=TfLiteInterpreterGetInputTensor(it,0);
    require(in && TfLiteTensorType(in)==kTfLiteInt8 && TfLiteTensorNumDims(in)==3 &&
            TfLiteTensorDim(in,0)==1 && TfLiteTensorDim(in,1)==3 && TfLiteTensorDim(in,2)==40 &&
            TfLiteTensorByteSize(in)==sizeof(buf),"input");
    uint64_t a=now();
    require(TfLiteTensorCopyFromBuffer(in,buf,sizeof(buf))==kTfLiteOk,"copy");
    uint64_t b=now();
    require(TfLiteInterpreterInvoke(it)==kTfLiteOk,"invoke");
    uint64_t c=now();
    const TfLiteTensor *out=TfLiteInterpreterGetOutputTensor(it,0);
    uint8_t value;
    require(out && TfLiteTensorType(out)==kTfLiteUInt8 && TfLiteTensorNumDims(out)==2 &&
            TfLiteTensorDim(out,0)==1 && TfLiteTensorDim(out,1)==1 && TfLiteTensorByteSize(out)==1 &&
            TfLiteTensorCopyToBuffer(out,&value,1)==kTfLiteOk,"output");
    uint64_t d=now();
    return (struct sample){b-a,c-b,d-c,d-start,value};
}
static void sequence(const char *label,TfLiteInterpreter *it) {
    printf("sequence %s ",label);
    for(unsigned i=0;i<16;i++) printf("%02x",(unsigned)step(it,128+i).value);
    puts("");
}
static void state(TfLiteModel *m,const char *path) {
    const char *modes[]={"persistent","reset","allocate","recreate","newmodel"};
    for(unsigned i=0;i<5;i++) {
        TfLiteInterpreter *it=create(m); allocate(it);
        sequence("initial",it);
        if(i==1) require(TfLiteInterpreterResetVariableTensors(it)==kTfLiteOk,"reset");
        if(i==2) allocate(it);
        TfLiteModel *other=NULL;
        if(i>=3) {
            TfLiteInterpreterDelete(it);
            if(i==4) {other=TfLiteModelCreateFromFile(path);require(other!=NULL,"newmodel");}
            it=create(other?other:m); allocate(it);
        }
        sequence(modes[i],it); TfLiteInterpreterDelete(it);
        if(other) TfLiteModelDelete(other);
    }
}
int main(int argc,char **argv) {
    require(argc==3,"args");
    printf("caps=%lx,%lx\n",getauxval(AT_HWCAP),getauxval(AT_HWCAP2));
    checkpoint("start",0);
    uint64_t t=now();
    TfLiteModel *m=TfLiteModelCreateFromFile(argv[1]);
    require(m!=NULL,"model");
    printf("time model %"PRIu64"\n",now()-t);
    if(!strcmp(argv[2],"badsize")) {
        TfLiteInterpreter *it=create(m); allocate(it);
        TfLiteTensor *in=TfLiteInterpreterGetInputTensor(it,0);
        int8_t short_input[119]={0};
        require(in && TfLiteTensorCopyFromBuffer(in,short_input,sizeof(short_input))!=kTfLiteOk,"badsize");
        TfLiteInterpreterDelete(it);
    } else if(!strcmp(argv[2],"state")) state(m,argv[1]);
    else if(!strcmp(argv[2],"stress")) {
        checkpoint("model",0); t=now();
        TfLiteInterpreter *it=create(m);
        printf("time create %"PRIu64"\n",now()-t); checkpoint("create",0);
        t=now(); allocate(it); printf("time allocate %"PRIu64"\n",now()-t);
        printf("variables %d\n",TfLiteInterpreterGetVariableTensorCount(it));
        checkpoint("allocated",0);
        for(unsigned i=0;i<200;i++) {
            struct sample s=step(it,i);
            if(!i) printf("time cold %"PRIu64"\n",s.invoke);
        }
        checkpoint("steady",0);
        FILE *samples=fopen("work/latency-private.txt","w");require(samples!=NULL,"metrics");
        for(unsigned i=0;i<10000;i++) {
            struct sample s=step(it,i);
            require(fprintf(samples,"%"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %u\n",
                    s.copy,s.invoke,s.read,s.total,(unsigned)s.value)>0,"metrics-write");
            completed++;
            if(completed%250==0) checkpoint("steady",completed);
        }
        require(fclose(samples)==0,"metrics-close");
        TfLiteInterpreterDelete(it); checkpoint("destroy",completed);
    } else if(!strcmp(argv[2],"lifecycle") || !strcmp(argv[2],"fullcycle")) {
        int full=!strcmp(argv[2],"fullcycle");
        for(unsigned i=0;i<1000;i++) {
            TfLiteModel *model=full?TfLiteModelCreateFromFile(argv[1]):m;
            require(model!=NULL,"reload"); TfLiteInterpreter *it=create(model); allocate(it);
            for(unsigned j=0;j<3;j++) step(it,j);
            TfLiteInterpreterDelete(it); if(full) TfLiteModelDelete(model);
            if((i+1)%50==0) checkpoint("cycle",i+1);
        }
    } else require(0,"mode");
    TfLiteModelDelete(m); checkpoint("end",completed);
    return 0;
}
