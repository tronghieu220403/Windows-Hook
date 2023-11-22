#include "asmencoder.h"

namespace assembly
{
    AssemblyEncoder::AssemblyEncoder(const ZydisEncoderRequest &req):
        req_(req)
    {

    }

    bool AssemblyEncoder::EncodeInstruction()
    {
        ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize encoded_length = sizeof(encoded_instruction);

        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req_, encoded_instruction, &encoded_length)))
        {
            return false;
        }

        for (ZyanUSize i = 0; i < encoded_length; ++i)
        {
            bytes_code_.push_back(encoded_instruction[i]);
        }

        return true;
    }

    void AssemblyEncoder::SetZydisEncoderRequest(const ZydisEncoderRequest& req)
    {
        req_ = req;
    }

    ZydisEncoderRequest AssemblyEncoder::GetZydisEncoderRequest() const
    {
        return req_;
    }

    std::vector<UCHAR> AssemblyEncoder::GetEncodedBytesCode() const
    {
        return bytes_code_;
    }

    void AssemblyEncoder::SetEncodedBytesCode(const std::vector<UCHAR>& bytes_code)
    {
        bytes_code_ = bytes_code;
    }

}
