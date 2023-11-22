#ifndef USERMODEHOOK_ASM_ASMENCODER_H_
#define USERMODEHOOK_ASM_ASMENCODER_H_

#include "ulti/everything.h"
#include "Zydis/Zydis.h"

namespace assembly
{
    class AssemblyEncoder
    {
    private:
        ZydisEncoderRequest req_;
        std::vector<UCHAR> bytes_code_;
    public:
        AssemblyEncoder() = default;
        AssemblyEncoder(const ZydisEncoderRequest& req);
        
        bool EncodeInstruction();

        void SetZydisEncoderRequest(const ZydisEncoderRequest& req);
        ZydisEncoderRequest GetZydisEncoderRequest() const;
        
        std::vector<UCHAR> GetEncodedBytesCode() const;
        void SetEncodedBytesCode(const std::vector<UCHAR>& bytes_code_);

    };
}

#endif