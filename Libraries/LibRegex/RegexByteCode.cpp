/*
 * Copyright (c) 2020, Emanuel Sprung <emanuel.sprung@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "RegexByteCode.h"
#include "RegexDebug.h"

#include <AK/StringBuilder.h>

namespace regex {

StringView execution_result_name(ExecutionResult result)
{
    switch (result) {
#define __ENUMERATE_EXECUTION_RESULT(x) \
    case ExecutionResult::x:            \
        return #x##sv;
        ENUMERATE_EXECUTION_RESULTS
#undef __ENUMERATE_EXECUTION_RESULT
    default:
        VERIFY_NOT_REACHED();
        return "<Unknown>"sv;
    }
}

StringView opcode_id_name(OpCodeId opcode)
{
    switch (opcode) {
#define __ENUMERATE_OPCODE(x) \
    case OpCodeId::x:         \
        return #x##sv;

        ENUMERATE_OPCODES

#undef __ENUMERATE_OPCODE
    default:
        VERIFY_NOT_REACHED();
        return "<Unknown>"sv;
    }
}

StringView fork_if_condition_name(ForkIfCondition condition)
{
    switch (condition) {
#define __ENUMERATE_FORK_IF_CONDITION(x) \
    case ForkIfCondition::x:             \
        return #x##sv;
        ENUMERATE_FORK_IF_CONDITIONS
#undef __ENUMERATE_FORK_IF_CONDITION
    default:
        return "<Unknown>"sv;
    }
}

StringView boundary_check_type_name(BoundaryCheckType ty)
{
    switch (ty) {
#define __ENUMERATE_BOUNDARY_CHECK_TYPE(x) \
    case BoundaryCheckType::x:             \
        return #x##sv;
        ENUMERATE_BOUNDARY_CHECK_TYPES
#undef __ENUMERATE_BOUNDARY_CHECK_TYPE
    default:
        VERIFY_NOT_REACHED();
        return "<Unknown>"sv;
    }
}

StringView character_compare_type_name(CharacterCompareType ch_compare_type)
{
    switch (ch_compare_type) {
#define __ENUMERATE_CHARACTER_COMPARE_TYPE(x) \
    case CharacterCompareType::x:             \
        return #x##sv;
        ENUMERATE_CHARACTER_COMPARE_TYPES
#undef __ENUMERATE_CHARACTER_COMPARE_TYPE
    default:
        VERIFY_NOT_REACHED();
        return "<Unknown>"sv;
    }
}

StringView character_class_name(CharClass ch_class)
{
    switch (ch_class) {
#define __ENUMERATE_CHARACTER_CLASS(x) \
    case CharClass::x:                 \
        return #x##sv;
        ENUMERATE_CHARACTER_CLASSES
#undef __ENUMERATE_CHARACTER_CLASS
    default:
        VERIFY_NOT_REACHED();
        return "<Unknown>"sv;
    }
}

void reverse_string_position(MatchState& state, RegexStringView view, size_t amount)
{
    VERIFY(state.string_position >= amount);
    state.string_position -= amount;

    if (view.unicode())
        state.string_position_in_code_units = view.code_unit_offset_of(state.string_position);
    else
        state.string_position_in_code_units -= amount;
}

void save_string_position(MatchInput const& input, MatchState const& state)
{
    input.saved_positions.append(state.string_position);
    input.saved_forks_since_last_save.append(state.forks_since_last_save);
    input.saved_code_unit_positions.append(state.string_position_in_code_units);
}

bool restore_string_position(MatchInput const& input, MatchState& state)
{
    if (input.saved_positions.is_empty())
        return false;

    state.string_position = input.saved_positions.take_last();
    state.string_position_in_code_units = input.saved_code_unit_positions.take_last();
    state.forks_since_last_save = input.saved_forks_since_last_save.take_last();
    return true;
}

bool is_word_character(u32 code_point, bool case_insensitive, bool unicode_mode)
{
    if (is_ascii_alphanumeric(code_point) || code_point == '_')
        return true;

    if (case_insensitive && unicode_mode) {
        auto canonical = Unicode::canonicalize(code_point, unicode_mode);
        if (is_ascii_alphanumeric(canonical) || canonical == '_')
            return true;
    }

    return false;
}

OwnPtr<OpCode<ByteCode>> ByteCode::s_opcodes[(size_t)OpCodeId::Last + 1];
bool ByteCode::s_opcodes_initialized { false };

OwnPtr<OpCode<FlatByteCode>> FlatByteCode::s_opcodes[(size_t)OpCodeId::Last + 1];
bool FlatByteCode::s_opcodes_initialized { false };

size_t ByteCode::s_next_checkpoint_serial_id { 0 };
u32 s_next_string_table_serial { 1 };
static u32 s_next_string_set_table_serial { 1 };

StringSetTable::StringSetTable()
    : m_serial(s_next_string_set_table_serial++)
{
}

StringSetTable::~StringSetTable()
{
    if (m_serial == s_next_string_set_table_serial - 1 && m_u8_tries.is_empty())
        --s_next_string_set_table_serial;
}

StringSetTable::StringSetTable(StringSetTable const& other)
    : m_serial(s_next_string_set_table_serial++)
{
    for (auto const& entry : other.m_u8_tries)
        m_u8_tries.set(entry.key, MUST(const_cast<StringSetTrie&>(entry.value).deep_copy()));
    for (auto const& entry : other.m_u16_tries)
        m_u16_tries.set(entry.key, MUST(const_cast<StringSetTrie&>(entry.value).deep_copy()));
}

StringSetTable& StringSetTable::operator=(StringSetTable const& other)
{
    if (this != &other) {
        m_u8_tries.clear();
        m_u16_tries.clear();
        for (auto const& entry : other.m_u8_tries)
            m_u8_tries.set(entry.key, MUST(const_cast<StringSetTrie&>(entry.value).deep_copy()));
        for (auto const& entry : other.m_u16_tries)
            m_u16_tries.set(entry.key, MUST(const_cast<StringSetTrie&>(entry.value).deep_copy()));
    }
    return *this;
}

void ByteCode::ensure_opcodes_initialized()
{
    if (s_opcodes_initialized)
        return;
    for (u32 i = (u32)OpCodeId::First; i <= (u32)OpCodeId::Last; ++i) {
        switch ((OpCodeId)i) {
#define __ENUMERATE_OPCODE(OpCode)                        \
    case OpCodeId::OpCode:                                \
        s_opcodes[i] = make<OpCode_##OpCode<ByteCode>>(); \
        break;

            ENUMERATE_OPCODES

#undef __ENUMERATE_OPCODE
        }
    }
    s_opcodes_initialized = true;
}

void FlatByteCode::ensure_opcodes_initialized()
{
    if (s_opcodes_initialized)
        return;
    for (u32 i = (u32)OpCodeId::First; i <= (u32)OpCodeId::Last; ++i) {
        switch ((OpCodeId)i) {
#define __ENUMERATE_OPCODE(OpCode)                            \
    case OpCodeId::OpCode:                                    \
        s_opcodes[i] = make<OpCode_##OpCode<FlatByteCode>>(); \
        break;

            ENUMERATE_OPCODES

#undef __ENUMERATE_OPCODE
        }
    }
    s_opcodes_initialized = true;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_SaveModifiers<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    auto current_flags = to_underlying(state.current_options.value());
    state.modifier_stack.append(current_flags);
    state.current_options = AllOptions { static_cast<AllFlags>(new_modifiers()) };
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_RestoreModifiers<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    if (state.modifier_stack.is_empty())
        return ExecutionResult::Failed;

    auto previous_modifiers = state.modifier_stack.take_last();
    state.current_options = AllOptions { static_cast<AllFlags>(previous_modifiers) };
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_Exit<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (state.string_position > input.view.length() || state.instruction_position >= bytecode().size())
        return ExecutionResult::Succeeded;

    return ExecutionResult::Failed;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_Save<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    save_string_position(input, state);
    state.forks_since_last_save = 0;
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_Restore<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (!restore_string_position(input, state))
        return ExecutionResult::Failed;
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_GoBack<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (count() > state.string_position)
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    reverse_string_position(state, input.view, count());
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_SetStepBack<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    state.step_backs.append(step());
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_IncStepBack<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (state.step_backs.is_empty())
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    size_t last_step_back = static_cast<size_t>(++state.step_backs.mutable_last());

    if (last_step_back > state.string_position)
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    reverse_string_position(state, input.view, last_step_back);
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_CheckStepBack<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (state.step_backs.is_empty())
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    if (input.saved_positions.is_empty())
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    // NOTE: Fail if the step-back would move before the lookbehind start.
    if (static_cast<size_t>(state.step_backs.last()) > input.saved_positions.last())
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    // NOTE: Restores the string position saved before executing a lookbehind.
    state.string_position = input.saved_positions.last();
    state.string_position_in_code_units = input.saved_code_unit_positions.last();
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_CheckSavedPosition<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (input.saved_positions.is_empty())
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    if (state.string_position != input.saved_positions.last())
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    state.step_backs.take_last();
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_FailForks<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    input.fail_counter += state.forks_since_last_save;
    return ExecutionResult::Failed_ExecuteLowPrioForks;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_PopSaved<ByteCode>::execute(MatchInput const& input, MatchState&) const
{
    if (input.saved_positions.is_empty() || input.saved_code_unit_positions.is_empty())
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    input.saved_positions.take_last();
    input.saved_code_unit_positions.take_last();
    return ExecutionResult::Failed_ExecuteLowPrioForks;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_Jump<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    state.instruction_position += offset();
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_ForkJump<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    state.fork_at_position = state.instruction_position + size() + offset();
    state.forks_since_last_save++;
    return ExecutionResult::Fork_PrioHigh;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_ForkReplaceJump<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    state.fork_at_position = state.instruction_position + size() + offset();
    input.fork_to_replace = state.instruction_position;
    state.forks_since_last_save++;
    return ExecutionResult::Fork_PrioHigh;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_ForkStay<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    state.fork_at_position = state.instruction_position + size() + offset();
    state.forks_since_last_save++;
    return ExecutionResult::Fork_PrioLow;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_ForkReplaceStay<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    state.fork_at_position = state.instruction_position + size() + offset();
    input.fork_to_replace = state.instruction_position;
    return ExecutionResult::Fork_PrioLow;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_ForkIf<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    auto next_step = [&](bool do_fork) -> ExecutionResult {
        switch (form()) {
        case OpCodeId::ForkJump:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + size() + offset();
                state.forks_since_last_save++;
                return ExecutionResult::Fork_PrioHigh;
            }
            return ExecutionResult::Continue;
        case OpCodeId::ForkReplaceJump:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + size() + offset();
                input.fork_to_replace = state.instruction_position;
                state.forks_since_last_save++;
                return ExecutionResult::Fork_PrioHigh;
            }
            return ExecutionResult::Continue;
        case OpCodeId::ForkStay:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + size() + offset();
                state.forks_since_last_save++;
                return ExecutionResult::Fork_PrioLow;
            }
            state.instruction_position += offset();
            return ExecutionResult::Continue;
        case OpCodeId::ForkReplaceStay:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + size() + offset();
                input.fork_to_replace = state.instruction_position;
                return ExecutionResult::Fork_PrioLow;
            }
            state.instruction_position += offset();
            return ExecutionResult::Continue;
        default:
            VERIFY_NOT_REACHED();
        }
    };

    switch (condition()) {
    case ForkIfCondition::AtStartOfLine:
        return next_step(!input.in_the_middle_of_a_line);
    case ForkIfCondition::Invalid:
    default:
        VERIFY_NOT_REACHED();
    }
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_CheckBegin<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    auto is_at_line_boundary = [&] {
        if (state.string_position == 0)
            return true;

        if (state.current_options.has_flag_set(AllFlags::Multiline) && state.current_options.has_flag_set(AllFlags::Internal_ConsiderNewline)) {
            auto input_view = input.view.substring_view(state.string_position - 1, 1).code_point_at(0);
            return input_view == '\r' || input_view == '\n' || input_view == LineSeparator || input_view == ParagraphSeparator;
        }

        return false;
    }();

    if (is_at_line_boundary && (state.current_options & AllFlags::MatchNotBeginOfLine))
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    if ((is_at_line_boundary && !(state.current_options & AllFlags::MatchNotBeginOfLine))
        || (!is_at_line_boundary && (state.current_options & AllFlags::MatchNotBeginOfLine))
        || (is_at_line_boundary && (state.current_options & AllFlags::Global)))
        return ExecutionResult::Continue;

    return ExecutionResult::Failed_ExecuteLowPrioForks;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_CheckBoundary<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    auto isword = [&](auto ch) {
        return is_word_character(ch, state.current_options & AllFlags::Insensitive, input.view.unicode());
    };
    auto is_word_boundary = [&] {
        if (state.string_position == input.view.length()) {
            return (state.string_position > 0 && isword(input.view.code_point_at(state.string_position_in_code_units - 1)));
        }

        if (state.string_position == 0) {
            return (isword(input.view.code_point_at(0)));
        }

        return !!(isword(input.view.code_point_at(state.string_position_in_code_units)) ^ isword(input.view.code_point_at(state.string_position_in_code_units - 1)));
    };
    switch (type()) {
    case BoundaryCheckType::Word: {
        if (is_word_boundary())
            return ExecutionResult::Continue;
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    }
    case BoundaryCheckType::NonWord: {
        if (!is_word_boundary())
            return ExecutionResult::Continue;
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    }
    }
    VERIFY_NOT_REACHED();
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_CheckEnd<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    auto is_at_line_boundary = [&] {
        if (state.string_position == input.view.length())
            return true;

        if (state.current_options.has_flag_set(AllFlags::Multiline) && state.current_options.has_flag_set(AllFlags::Internal_ConsiderNewline)) {
            auto input_view = input.view.substring_view(state.string_position, 1).code_point_at(0);
            return input_view == '\r' || input_view == '\n' || input_view == LineSeparator || input_view == ParagraphSeparator;
        }

        return false;
    }();
    if (is_at_line_boundary && (state.current_options & AllFlags::MatchNotEndOfLine))
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    if ((is_at_line_boundary && !(state.current_options & AllFlags::MatchNotEndOfLine))
        || (!is_at_line_boundary && (state.current_options & AllFlags::MatchNotEndOfLine || state.current_options & AllFlags::MatchNotBeginOfLine)))
        return ExecutionResult::Continue;

    return ExecutionResult::Failed_ExecuteLowPrioForks;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_ClearCaptureGroup<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (input.match_index < state.capture_group_matches_size()) {
        auto group = state.mutable_capture_group_matches(input.match_index);
        group[id() - 1].reset();
    }
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_FailIfEmpty<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    u64 current_position = state.string_position + 1;
    auto checkpoint_position = state.checkpoints.get(checkpoint()).value_or(current_position);

    if (checkpoint_position == current_position) {
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    }

    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_SaveLeftCaptureGroup<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    if (input.match_index >= state.capture_group_matches_size()) {
        state.flat_capture_group_matches.ensure_capacity((input.match_index + 1) * state.capture_group_count);
        for (size_t i = state.capture_group_matches_size(); i <= input.match_index; ++i)
            for (size_t j = 0; j < state.capture_group_count; ++j)
                state.flat_capture_group_matches.append({});
    }

    state.mutable_capture_group_matches(input.match_index).at(id() - 1).left_column = state.string_position;
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_SaveRightCaptureGroup<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    auto& match = state.capture_group_matches(input.match_index).at(id() - 1);
    auto start_position = match.left_column;
    if (state.string_position < start_position) {
        dbgln("Right capture group {} is before left capture group {}!", state.string_position, start_position);
        return ExecutionResult::Failed_ExecuteLowPrioForks;
    }

    auto length = state.string_position - start_position;

    if (start_position < match.column && state.step_backs.is_empty())
        return ExecutionResult::Continue;

    VERIFY(start_position + length <= input.view.length_in_code_units());

    auto captured_text = input.view.substring_view(start_position, length);

    // NOTE: Don't overwrite existing capture with empty match at the same position. The ECMA-262 RepeatMatcher
    // continuation chain effectively preserves captures when an empty match occurs at the position where the
    // existing capture ended.
    // See: https://tc39.es/ecma262/#step-repeatmatcher-done
    auto& existing_capture = state.mutable_capture_group_matches(input.match_index).at(id() - 1);
    if (length == 0 && !existing_capture.view.is_null() && existing_capture.view.length() > 0) {
        auto existing_end_position = existing_capture.global_offset - input.global_offset + existing_capture.view.length();
        if (existing_end_position == state.string_position) {
            return ExecutionResult::Continue;
        }
    }

    state.mutable_capture_group_matches(input.match_index).at(id() - 1) = { captured_text, input.line, start_position, input.global_offset + start_position };

    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_SaveRightNamedCaptureGroup<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    auto& match = state.capture_group_matches(input.match_index).at(id() - 1);
    auto start_position = match.left_column;
    if (state.string_position < start_position)
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    auto length = state.string_position - start_position;

    if (start_position < match.column)
        return ExecutionResult::Continue;

    VERIFY(start_position + length <= input.view.length_in_code_units());

    auto view = input.view.substring_view(start_position, length);

    // Same logic as in SaveRightCaptureGroup above.
    // https://tc39.es/ecma262/#step-repeatmatcher-done
    auto& existing_capture = state.mutable_capture_group_matches(input.match_index).at(id() - 1);
    if (length == 0 && !existing_capture.view.is_null() && existing_capture.view.length() > 0) {
        auto existing_end_position = existing_capture.global_offset - input.global_offset + existing_capture.view.length();
        if (existing_end_position == state.string_position) {
            return ExecutionResult::Continue;
        }
    }

    state.mutable_capture_group_matches(input.match_index).at(id() - 1) = { view, name_string_table_index(), input.line, start_position, input.global_offset + start_position };

    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_RSeekTo<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    auto ch = argument(0);

    size_t search_from;
    size_t search_from_in_code_units;
    auto line_limited = false;

    if (state.string_position_before_rseek == NumericLimits<size_t>::max()) {
        state.string_position_before_rseek = state.string_position;
        state.string_position_in_code_units_before_rseek = state.string_position_in_code_units;

        if (!input.regex_options.has_flag_set(AllFlags::SingleLine)) {
            auto end_of_line = input.view.find_end_of_line(state.string_position, state.string_position_in_code_units);
            search_from = end_of_line.code_point_index + 1;
            search_from_in_code_units = end_of_line.code_unit_index + 1;
            line_limited = true;
        } else {
            search_from = NumericLimits<size_t>::max();
            search_from_in_code_units = NumericLimits<size_t>::max();
        }
    } else {
        search_from = state.string_position;
        search_from_in_code_units = state.string_position_in_code_units;
    }

    auto next = input.view.find_index_of_previous(ch, search_from, search_from_in_code_units);
    if (!next.has_value() || next->code_unit_index < state.string_position_in_code_units_before_rseek) {
        if (line_limited)
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        return ExecutionResult::Failed_ExecuteLowPrioForksButNoFurtherPossibleMatches;
    }
    state.string_position = next->code_point_index;
    state.string_position_in_code_units = next->code_unit_index;
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ByteString OpCode_Compare<ByteCode>::arguments_string() const
{
    return ByteString::formatted("argc={}, args={} ", arguments_count(), arguments_size());
}

template<typename ByteCode, bool IsSimple>
Vector<CompareTypeAndValuePair> CompareInternals<ByteCode, IsSimple>::flat_compares() const
{
    Vector<CompareTypeAndValuePair> result;

    size_t offset { state().instruction_position + (IsSimple ? 2 : 3) };
    auto argument_count = IsSimple ? 1 : argument(0);
    auto& bytecode = this->bytecode();

    for (size_t i = 0; i < argument_count; ++i) {
        auto compare_type = (CharacterCompareType)bytecode[offset++];

        if (compare_type == CharacterCompareType::Char) {
            auto ch = bytecode[offset++];
            result.append({ compare_type, ch });
        } else if (compare_type == CharacterCompareType::Reference) {
            auto ref = bytecode[offset++];
            result.append({ compare_type, ref });
        } else if (compare_type == CharacterCompareType::NamedReference) {
            auto ref = bytecode[offset++];
            result.append({ compare_type, ref });
        } else if (compare_type == CharacterCompareType::String) {
            auto string_index = bytecode[offset++];
            result.append({ compare_type, string_index });
        } else if (compare_type == CharacterCompareType::CharClass) {
            auto character_class = bytecode[offset++];
            result.append({ compare_type, character_class });
        } else if (compare_type == CharacterCompareType::CharRange) {
            auto value = bytecode[offset++];
            result.append({ compare_type, value });
        } else if (compare_type == CharacterCompareType::LookupTable) {
            auto count_sensitive = bytecode[offset++];
            auto count_insensitive = bytecode[offset++];
            for (size_t i = 0; i < count_sensitive; ++i)
                result.append({ CharacterCompareType::CharRange, bytecode[offset++] });
            offset += count_insensitive; // Skip insensitive ranges
        } else if (compare_type == CharacterCompareType::GeneralCategory
            || compare_type == CharacterCompareType::Property
            || compare_type == CharacterCompareType::Script
            || compare_type == CharacterCompareType::ScriptExtension
            || compare_type == CharacterCompareType::StringSet) {
            auto value = bytecode[offset++];
            result.append({ compare_type, value });
        } else {
            result.append({ compare_type, 0 });
        }
    }
    return result;
}

template<typename ByteCode>
ByteString OpCode_CompareSimple<ByteCode>::arguments_string() const
{
    StringBuilder builder;
    auto type = (CharacterCompareType)argument(1);
    builder.append(character_compare_type_name(type));
    switch (type) {
    case CharacterCompareType::Char: {
        auto ch = argument(2);
        if (is_ascii_printable(ch))
            builder.append(ByteString::formatted(" '{:c}'", static_cast<char>(ch)));
        else
            builder.append(ByteString::formatted(" 0x{:x}", ch));
        break;
    }
    case CharacterCompareType::String: {
        auto string_index = argument(2);
        auto string = this->bytecode().get_u16_string(string_index);
        builder.appendff(" \"{}\"", string);
        break;
    }
    case CharacterCompareType::CharClass: {
        auto character_class = (CharClass)argument(2);
        builder.appendff(" {}", character_class_name(character_class));
        break;
    }
    case CharacterCompareType::Reference: {
        auto ref = argument(2);
        builder.appendff(" number={}", ref);
        break;
    }
    case CharacterCompareType::NamedReference: {
        auto ref = argument(2);
        builder.appendff(" named_number={}", ref);
        break;
    }
    case CharacterCompareType::GeneralCategory:
    case CharacterCompareType::Property:
    case CharacterCompareType::Script:
    case CharacterCompareType::ScriptExtension:
    case CharacterCompareType::StringSet: {
        builder.appendff(" value={}", argument(2));
        break;
    }
    case CharacterCompareType::LookupTable: {
        auto count_sensitive = argument(2);
        auto count_insensitive = argument(3);
        for (size_t j = 0; j < count_sensitive; ++j) {
            auto range = (CharRange)argument(4 + j);
            builder.appendff(" {:x}-{:x}", range.from, range.to);
        }
        if (count_insensitive > 0) {
            builder.append(" [insensitive ranges:"sv);
            for (size_t j = 0; j < count_insensitive; ++j) {
                auto range = (CharRange)argument(4 + count_sensitive + j);
                builder.appendff("  {:x}-{:x}", range.from, range.to);
            }
            builder.append(" ]"sv);
        }
        break;
    }
    case CharacterCompareType::CharRange: {
        auto value = argument(2);
        auto range = (CharRange)value;
        builder.appendff(" {:x}-{:x}", range.from, range.to);
        break;
    }
    default:
        break;
    }

    return builder.to_byte_string();
}

template<typename ByteCode>
Vector<ByteString> OpCode_Compare<ByteCode>::variable_arguments_to_byte_string(Optional<MatchInput const&> input) const
{
    Vector<ByteString> result;

    size_t offset { state().instruction_position + 3 };
    RegexStringView const& view = input.has_value() ? input.value().view : StringView {};

    auto argument_count = arguments_count();
    auto& bytecode = this->bytecode();

    for (size_t i = 0; i < argument_count; ++i) {
        auto compare_type = (CharacterCompareType)bytecode[offset++];
        result.empend(ByteString::formatted("type={} [{}]", (size_t)compare_type, character_compare_type_name(compare_type)));

        auto string_start_offset = state().string_position_before_match;

        if (compare_type == CharacterCompareType::Char) {
            auto ch = bytecode[offset++];
            auto is_ascii = is_ascii_printable(ch);
            if (is_ascii)
                result.empend(ByteString::formatted(" value='{:c}'", static_cast<char>(ch)));
            else
                result.empend(ByteString::formatted(" value={:x}", ch));

            if (!view.is_null() && view.length() > string_start_offset) {
                if (is_ascii) {
                    result.empend(ByteString::formatted(
                        " compare against: '{}'",
                        view.substring_view(string_start_offset, string_start_offset > view.length() ? 0 : 1).to_byte_string()));
                } else {
                    auto str = view.substring_view(string_start_offset, string_start_offset > view.length() ? 0 : 1).to_byte_string();
                    u8 buf[8] { 0 };
                    __builtin_memcpy(buf, str.characters(), min(str.length(), sizeof(buf)));
                    result.empend(ByteString::formatted(" compare against: {:x},{:x},{:x},{:x},{:x},{:x},{:x},{:x}",
                        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]));
                }
            }
        } else if (compare_type == CharacterCompareType::Reference) {
            auto ref = bytecode[offset++];
            result.empend(ByteString::formatted(" number={}", ref));
            if (input.has_value()) {
                if (state().capture_group_matches_size() > input->match_index) {
                    auto match = state().capture_group_matches(input->match_index);
                    if (match.size() > ref) {
                        auto& group = match[ref];
                        result.empend(ByteString::formatted(" left={}", group.left_column));
                        result.empend(ByteString::formatted(" right={}", group.left_column + group.view.length_in_code_units()));
                        result.empend(ByteString::formatted(" contents='{}'", group.view));
                    } else {
                        result.empend(ByteString::formatted(" (invalid ref, max={})", match.size() - 1));
                    }
                } else {
                    result.empend(ByteString::formatted(" (invalid index {}, max={})", input->match_index, state().capture_group_matches_size() - 1));
                }
            }
        } else if (compare_type == CharacterCompareType::NamedReference) {
            auto ref = bytecode[offset++];
            result.empend(ByteString::formatted(" named_number={}", ref));
            if (input.has_value()) {
                if (state().capture_group_matches_size() > input->match_index) {
                    auto match = state().capture_group_matches(input->match_index);
                    if (match.size() > ref) {
                        auto& group = match[ref];
                        result.empend(ByteString::formatted(" left={}", group.left_column));
                        result.empend(ByteString::formatted(" right={}", group.left_column + group.view.length_in_code_units()));
                        result.empend(ByteString::formatted(" contents='{}'", group.view));
                    } else {
                        result.empend(ByteString::formatted(" (invalid ref {}, max={})", ref, match.size() - 1));
                    }
                } else {
                    result.empend(ByteString::formatted(" (invalid index {}, max={})", input->match_index, state().capture_group_matches_size() - 1));
                }
            }
        } else if (compare_type == CharacterCompareType::String) {
            auto id = bytecode[offset++];
            auto string = this->bytecode().get_u16_string(id);
            result.empend(ByteString::formatted(" value=\"{}\"", string));
            if (!view.is_null() && view.length() > state().string_position)
                result.empend(ByteString::formatted(
                    " compare against: \"{}\"",
                    input.value().view.substring_view(string_start_offset, string_start_offset + string.length_in_code_units() > view.length() ? 0 : string.length_in_code_units()).to_byte_string()));
        } else if (compare_type == CharacterCompareType::CharClass) {
            auto character_class = (CharClass)bytecode[offset++];
            result.empend(ByteString::formatted(" ch_class={} [{}]", (size_t)character_class, character_class_name(character_class)));
            if (!view.is_null() && view.length() > state().string_position)
                result.empend(ByteString::formatted(
                    " compare against: '{}'",
                    input.value().view.substring_view(string_start_offset, state().string_position > view.length() ? 0 : 1).to_byte_string()));
        } else if (compare_type == CharacterCompareType::CharRange) {
            auto value = (CharRange)bytecode[offset++];
            result.empend(ByteString::formatted(" ch_range={:x}-{:x}", value.from, value.to));
            if (!view.is_null() && view.length() > state().string_position)
                result.empend(ByteString::formatted(
                    " compare against: '{}'",
                    input.value().view.substring_view(string_start_offset, state().string_position > view.length() ? 0 : 1).to_byte_string()));
        } else if (compare_type == CharacterCompareType::LookupTable) {
            auto count_sensitive = bytecode[offset++];
            auto count_insensitive = bytecode[offset++];
            for (size_t j = 0; j < count_sensitive; ++j) {
                auto range = (CharRange)bytecode[offset++];
                result.append(ByteString::formatted(" {:x}-{:x}", range.from, range.to));
            }
            if (count_insensitive > 0) {
                result.append(" [insensitive ranges:");
                for (size_t j = 0; j < count_insensitive; ++j) {
                    auto range = (CharRange)bytecode[offset++];
                    result.append(ByteString::formatted("  {:x}-{:x}", range.from, range.to));
                }
                result.append(" ]");
            }

            if (!view.is_null() && view.length() > state().string_position)
                result.empend(ByteString::formatted(
                    " compare against: '{}'",
                    input.value().view.substring_view(string_start_offset, state().string_position > view.length() ? 0 : 1).to_byte_string()));
        } else if (compare_type == CharacterCompareType::GeneralCategory
            || compare_type == CharacterCompareType::Property
            || compare_type == CharacterCompareType::Script
            || compare_type == CharacterCompareType::ScriptExtension
            || compare_type == CharacterCompareType::StringSet) {
            auto value = bytecode[offset++];
            result.empend(ByteString::formatted(" value={}", value));
        }
    }
    return result;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_Repeat<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    VERIFY(count() > 0);

    if (id() >= state.repetition_marks.size())
        state.repetition_marks.resize(id() + 1);
    auto& repetition_mark = state.repetition_marks.mutable_at(id());

    if (repetition_mark == count() - 1) {
        repetition_mark = 0;
    } else {
        state.instruction_position -= offset() + size();
        ++repetition_mark;
    }

    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_ResetRepeat<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    if (id() >= state.repetition_marks.size())
        state.repetition_marks.resize(id() + 1);

    state.repetition_marks.mutable_at(id()) = 0;
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_Checkpoint<ByteCode>::execute(MatchInput const&, MatchState& state) const
{
    auto id = this->id();
    if (id >= state.checkpoints.size())
        state.checkpoints.resize(id + 1);

    state.checkpoints.mutable_at(id) = state.string_position + 1;
    return ExecutionResult::Continue;
}

template<typename ByteCode>
ALWAYS_INLINE ExecutionResult OpCode_JumpNonEmpty<ByteCode>::execute(MatchInput const& input, MatchState& state) const
{
    u64 current_position = state.string_position;
    auto checkpoint_position = state.checkpoints.get(checkpoint()).value_or(0);

    if (checkpoint_position != 0 && checkpoint_position != current_position + 1) {
        auto form = this->form();

        if (form == OpCodeId::Jump) {
            state.instruction_position += offset();
            return ExecutionResult::Continue;
        }

        state.fork_at_position = state.instruction_position + size() + offset();

        if (form == OpCodeId::ForkJump) {
            state.forks_since_last_save++;
            return ExecutionResult::Fork_PrioHigh;
        }

        if (form == OpCodeId::ForkStay) {
            state.forks_since_last_save++;
            return ExecutionResult::Fork_PrioLow;
        }

        if (form == OpCodeId::ForkReplaceStay) {
            input.fork_to_replace = state.instruction_position;
            return ExecutionResult::Fork_PrioLow;
        }

        if (form == OpCodeId::ForkReplaceJump) {
            input.fork_to_replace = state.instruction_position;
            return ExecutionResult::Fork_PrioHigh;
        }
    }

    if (form() == OpCodeId::Jump && state.string_position < input.view.length())
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    return ExecutionResult::Continue;
}

template class CompareInternals<ByteCode, true>;
template class CompareInternals<ByteCode, false>;
template class CompareInternals<FlatByteCode, true>;
template class CompareInternals<FlatByteCode, false>;

#define __ENUMERATE_OPCODE(opcode)            \
    template class OpCode_##opcode<ByteCode>; \
    template class OpCode_##opcode<FlatByteCode>;
ENUMERATE_OPCODES
#undef __ENUMERATE_OPCODE

}
