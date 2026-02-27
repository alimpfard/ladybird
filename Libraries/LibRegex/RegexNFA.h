/*
 * Copyright (c) 2025, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "RegexByteCode.h"
#include "RegexMatch.h"
#include "RegexOptions.h"

#include <AK/Optional.h>
#include <AK/Vector.h>

namespace regex {

struct NFAMatcher {
    size_t bytecode_ip;
    Optional<u32> single_char;
};

struct NFANode {
    enum class Type : u8 {
        Match,
        Split,
        Accept,
        AssertBegin,
        AssertEnd,
        AssertBoundary,
        CaptureOpen,
        CaptureClose,
        ClearCapture,
        Checkpoint,
        FailIfEmpty,
        SaveModifiers,
        RestoreModifiers,
    };

    Type type;
    u32 out1 { 0 };
    u32 out2 { 0 };
    u32 data_index { 0 };
    bool boundary_negated {};
};

struct NFAGraph {
    Vector<NFANode> nodes;
    Vector<NFAMatcher> matchers;
    HashMap<u32, size_t> named_capture_group_names; // group_id -> name string table index
    u32 start { 0 };
    u32 accept { 0 };
    size_t capture_group_count { 0 };
    size_t checkpoint_count { 0 }; // max checkpoint id + 1
};

template<typename ByteCode>
bool qualifies_for_nfa_execution(ByteCode const& bytecode)
{
    auto const* data = bytecode.flat_data().data();
    auto bytecode_size = bytecode.size();

    if (bytecode_size == 0)
        return false;

    size_t ip = 0;
    size_t node_count = 0;
    while (ip < bytecode_size) {
        auto opcode_id = static_cast<OpCodeId>(data[ip]);
        ++node_count;

        switch (opcode_id) {
        case OpCodeId::Compare: {
            auto arguments_count = data[ip + 1];
            auto arguments_size = data[ip + 2];
            size_t offset = ip + 3;
            for (size_t i = 0; i < arguments_count; ++i) {
                auto ct = static_cast<CharacterCompareType>(data[offset]);
                if (ct == CharacterCompareType::Reference
                    || ct == CharacterCompareType::NamedReference
                    || ct == CharacterCompareType::String
                    || ct == CharacterCompareType::StringSet)
                    return false;
                switch (ct) {
                case CharacterCompareType::Inverse:
                case CharacterCompareType::TemporaryInverse:
                case CharacterCompareType::AnyChar:
                case CharacterCompareType::RangeExpressionDummy:
                case CharacterCompareType::And:
                case CharacterCompareType::Or:
                case CharacterCompareType::EndAndOr:
                case CharacterCompareType::Subtract:
                    offset += 1;
                    break;
                case CharacterCompareType::LookupTable: {
                    auto cs = data[offset + 1];
                    auto ci = data[offset + 2];
                    offset += 3 + cs + ci;
                    break;
                }
                default:
                    offset += 2;
                    break;
                }
            }
            ip += 3 + arguments_size;
            break;
        }
        case OpCodeId::CompareSimple: {
            auto arguments_size = data[ip + 1];
            auto ct = static_cast<CharacterCompareType>(data[ip + 2]);
            if (ct == CharacterCompareType::Reference
                || ct == CharacterCompareType::NamedReference
                || ct == CharacterCompareType::String
                || ct == CharacterCompareType::StringSet)
                return false;
            ip += 2 + arguments_size;
            break;
        }
        case OpCodeId::ForkJump:
        case OpCodeId::ForkStay:
        case OpCodeId::ForkReplaceJump:
        case OpCodeId::ForkReplaceStay:
        case OpCodeId::Jump:
        case OpCodeId::SaveLeftCaptureGroup:
        case OpCodeId::SaveRightCaptureGroup:
        case OpCodeId::ClearCaptureGroup:
        case OpCodeId::CheckBoundary:
        case OpCodeId::Checkpoint:
        case OpCodeId::FailIfEmpty:
        case OpCodeId::ResetRepeat:
        case OpCodeId::SaveModifiers:
            ip += 2;
            break;
        case OpCodeId::SaveRightNamedCaptureGroup:
            ip += 3;
            break;
        case OpCodeId::JumpNonEmpty:
            ip += 4;
            break;
        case OpCodeId::CheckBegin:
        case OpCodeId::CheckEnd:
        case OpCodeId::RestoreModifiers:
        case OpCodeId::Exit:
            ip += 1;
            break;
        // Unsupported opcodes
        case OpCodeId::Repeat:
        case OpCodeId::Save:
        case OpCodeId::Restore:
        case OpCodeId::GoBack:
        case OpCodeId::SetStepBack:
        case OpCodeId::IncStepBack:
        case OpCodeId::CheckStepBack:
        case OpCodeId::CheckSavedPosition:
        case OpCodeId::FailForks:
        case OpCodeId::PopSaved:
        case OpCodeId::ForkIf:
        case OpCodeId::RSeekTo:
            return false;
        }

        if (node_count > 10000)
            return false;
    }
    return true;
}

Optional<NFAGraph> build_nfa(FlatByteCode const& bytecode);

enum class NFAExecuteResult : u8 {
    Matched,
    DidNotMatch,
};

NFAExecuteResult execute_nfa(
    NFAGraph const& graph,
    FlatByteCode const& bytecode,
    MatchInput const& input,
    MatchState& state);

}
