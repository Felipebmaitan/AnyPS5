#ifndef RELINKER_DOMAIN_ISYSCALLSCANNER_HPP
#define RELINKER_DOMAIN_ISYSCALLSCANNER_HPP

#include <relinker/domain/Types.hpp>
#include <relinker/domain/RelinkResult.hpp>
#include <cstddef>
#include <vector>
#include <string_view>

namespace Relinker {

class ISyscallScanner {
public:
    virtual ~ISyscallScanner() = default;

    virtual std::vector<std::size_t> ScanCodeSectionForSyscalls(const std::vector<std::uint8_t>& codeSection, FileByteOffset codeSectionOffset, FileByteOffset codeSectionSize, std::string_view input = {}, const std::vector<CodeRange>& unwindRanges = {}) = 0;
    virtual std::vector<RelinkPatch> ScanReferencedTailForSyscalls(const std::vector<std::uint8_t>& bytes, const std::vector<ProgramHeader>& headers, std::string_view input = {}) = 0;
};

}

#endif
