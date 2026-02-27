/*
 * Copyright (c) 2020, Emanuel Sprung <emanuel.sprung@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "RegexBytecodeStreamOptimizer.h"
#include "RegexMatch.h"

#include <AK/BinarySearch.h>
#include <AK/CharacterTypes.h>
#include <AK/Concepts.h>
#include <AK/DisjointChunks.h>
#include <AK/Forward.h>
#include <AK/HashMap.h>
#include <AK/OwnPtr.h>
#include <AK/Trie.h>
#include <AK/TypeCasts.h>
#include <AK/Types.h>
#include <AK/Utf16FlyString.h>
#include <AK/Vector.h>
#include <LibUnicode/CharacterTypes.h>

namespace regex {

using ByteCodeValueType = u64;

#define ENUMERATE_OPCODES                          \
    __ENUMERATE_OPCODE(Compare)                    \
    __ENUMERATE_OPCODE(Jump)                       \
    __ENUMERATE_OPCODE(JumpNonEmpty)               \
    __ENUMERATE_OPCODE(ForkJump)                   \
    __ENUMERATE_OPCODE(ForkStay)                   \
    __ENUMERATE_OPCODE(ForkReplaceJump)            \
    __ENUMERATE_OPCODE(ForkReplaceStay)            \
    __ENUMERATE_OPCODE(ForkIf)                     \
    __ENUMERATE_OPCODE(FailForks)                  \
    __ENUMERATE_OPCODE(PopSaved)                   \
    __ENUMERATE_OPCODE(SaveLeftCaptureGroup)       \
    __ENUMERATE_OPCODE(SaveRightCaptureGroup)      \
    __ENUMERATE_OPCODE(SaveRightNamedCaptureGroup) \
    __ENUMERATE_OPCODE(RSeekTo)                    \
    __ENUMERATE_OPCODE(CheckBegin)                 \
    __ENUMERATE_OPCODE(CheckEnd)                   \
    __ENUMERATE_OPCODE(CheckBoundary)              \
    __ENUMERATE_OPCODE(Save)                       \
    __ENUMERATE_OPCODE(Restore)                    \
    __ENUMERATE_OPCODE(GoBack)                     \
    __ENUMERATE_OPCODE(SetStepBack)                \
    __ENUMERATE_OPCODE(IncStepBack)                \
    __ENUMERATE_OPCODE(CheckStepBack)              \
    __ENUMERATE_OPCODE(CheckSavedPosition)         \
    __ENUMERATE_OPCODE(ClearCaptureGroup)          \
    __ENUMERATE_OPCODE(FailIfEmpty)                \
    __ENUMERATE_OPCODE(Repeat)                     \
    __ENUMERATE_OPCODE(ResetRepeat)                \
    __ENUMERATE_OPCODE(Checkpoint)                 \
    __ENUMERATE_OPCODE(CompareSimple)              \
    __ENUMERATE_OPCODE(SaveModifiers)              \
    __ENUMERATE_OPCODE(RestoreModifiers)           \
    __ENUMERATE_OPCODE(Exit)

// clang-format off
enum class OpCodeId : ByteCodeValueType {
#define __ENUMERATE_OPCODE(x) x,
    ENUMERATE_OPCODES
#undef __ENUMERATE_OPCODE

    First = Compare,
    Last = Exit,
};
// clang-format on

#define ENUMERATE_CHARACTER_COMPARE_TYPES                    \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Undefined)            \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Inverse)              \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(TemporaryInverse)     \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(AnyChar)              \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Char)                 \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(String)               \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(CharClass)            \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(CharRange)            \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Reference)            \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(NamedReference)       \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Property)             \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(GeneralCategory)      \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Script)               \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(ScriptExtension)      \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(RangeExpressionDummy) \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(LookupTable)          \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(And)                  \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Or)                   \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(EndAndOr)             \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(Subtract)             \
    __ENUMERATE_CHARACTER_COMPARE_TYPE(StringSet)

enum class CharacterCompareType : ByteCodeValueType {
#define __ENUMERATE_CHARACTER_COMPARE_TYPE(x) x,
    ENUMERATE_CHARACTER_COMPARE_TYPES
#undef __ENUMERATE_CHARACTER_COMPARE_TYPE
};

#define ENUMERATE_CHARACTER_CLASSES    \
    __ENUMERATE_CHARACTER_CLASS(Alnum) \
    __ENUMERATE_CHARACTER_CLASS(Cntrl) \
    __ENUMERATE_CHARACTER_CLASS(Lower) \
    __ENUMERATE_CHARACTER_CLASS(Space) \
    __ENUMERATE_CHARACTER_CLASS(Alpha) \
    __ENUMERATE_CHARACTER_CLASS(Digit) \
    __ENUMERATE_CHARACTER_CLASS(Print) \
    __ENUMERATE_CHARACTER_CLASS(Upper) \
    __ENUMERATE_CHARACTER_CLASS(Blank) \
    __ENUMERATE_CHARACTER_CLASS(Graph) \
    __ENUMERATE_CHARACTER_CLASS(Punct) \
    __ENUMERATE_CHARACTER_CLASS(Word)  \
    __ENUMERATE_CHARACTER_CLASS(Xdigit)

enum class CharClass : ByteCodeValueType {
#define __ENUMERATE_CHARACTER_CLASS(x) x,
    ENUMERATE_CHARACTER_CLASSES
#undef __ENUMERATE_CHARACTER_CLASS
};

#define ENUMERATE_BOUNDARY_CHECK_TYPES    \
    __ENUMERATE_BOUNDARY_CHECK_TYPE(Word) \
    __ENUMERATE_BOUNDARY_CHECK_TYPE(NonWord)

enum class BoundaryCheckType : ByteCodeValueType {
#define __ENUMERATE_BOUNDARY_CHECK_TYPE(x) x,
    ENUMERATE_BOUNDARY_CHECK_TYPES
#undef __ENUMERATE_BOUNDARY_CHECK_TYPE
};

#define ENUMERATE_FORK_IF_CONDITIONS             \
    __ENUMERATE_FORK_IF_CONDITION(AtStartOfLine) \
    __ENUMERATE_FORK_IF_CONDITION(Invalid) /* Must be last */

enum class ForkIfCondition : ByteCodeValueType {
#define __ENUMERATE_FORK_IF_CONDITION(x) x,
    ENUMERATE_FORK_IF_CONDITIONS
#undef __ENUMERATE_FORK_IF_CONDITION
};

struct CharRange {
    u32 from;
    u32 to;

    CharRange(u64 value)
        : from(value >> 32)
        , to(value & 0xffffffff)
    {
    }

    CharRange(u32 from, u32 to)
        : from(from)
        , to(to)
    {
    }

    operator ByteCodeValueType() const { return ((u64)from << 32) | to; }
};

struct CompareTypeAndValuePair {
    CharacterCompareType type;
    ByteCodeValueType value;
};

REGEX_API extern u32 s_next_string_table_serial;

template<typename StringType>
struct StringTable {
    StringTable()
        : m_serial(s_next_string_table_serial++)
    {
    }
    ~StringTable()
    {
        if (m_serial != 0) {
            if (m_serial == s_next_string_table_serial - 1 && m_table.is_empty())
                --s_next_string_table_serial; // We didn't use this serial, put it back.
        }
    }
    StringTable(StringTable const& other)
    {
        // Pull a new serial for this copy
        m_serial = s_next_string_table_serial++;
        m_table = other.m_table;
        m_inverse_table = other.m_inverse_table;
    }
    StringTable(StringTable&& other)
    {
        m_serial = other.m_serial;
        m_table = move(other.m_table);
        m_inverse_table = move(other.m_inverse_table);
        // Clear other's data to avoid double-deletion of serial
        other.m_serial = 0;
    }
    StringTable& operator=(StringTable const& other)
    {
        if (this != &other) {
            m_serial = s_next_string_table_serial++;
            m_table = other.m_table;
            m_inverse_table = other.m_inverse_table;
        }
        return *this;
    }
    StringTable& operator=(StringTable&& other)
    {
        if (this != &other) {
            m_serial = other.m_serial;
            m_table = move(other.m_table);
            m_inverse_table = move(other.m_inverse_table);
            // Clear other's data to avoid double-deletion of serial
            other.m_serial = 0;
        }
        return *this;
    }

    ByteCodeValueType set(StringType string)
    {
        u32 local_index = m_table.size() + 0x4242;
        ByteCodeValueType global_index;
        if (auto maybe_local_index = m_table.get(string); maybe_local_index.has_value()) {
            local_index = maybe_local_index.value();
            global_index = static_cast<ByteCodeValueType>(m_serial) << 32 | static_cast<ByteCodeValueType>(local_index);
        } else {
            global_index = static_cast<ByteCodeValueType>(m_serial) << 32 | static_cast<ByteCodeValueType>(local_index);
            m_table.set(string, global_index);
            m_inverse_table.set(global_index, string);
        }

        return global_index;
    }

    StringType get(ByteCodeValueType index) const
    {
        return m_inverse_table.get(index).value();
    }

    u32 m_serial { 0 };
    HashMap<StringType, ByteCodeValueType> m_table;
    HashMap<ByteCodeValueType, StringType> m_inverse_table;
};

using StringSetTrie = Trie<u32, bool>;

struct REGEX_API StringSetTable {
    StringSetTable();
    ~StringSetTable();
    StringSetTable(StringSetTable const& other);
    StringSetTable(StringSetTable&&) = default;
    StringSetTable& operator=(StringSetTable const& other);
    StringSetTable& operator=(StringSetTable&&) = default;

    ByteCodeValueType set(Vector<String> const& strings)
    {
        u32 local_index = m_u8_tries.size();
        ByteCodeValueType global_index = static_cast<ByteCodeValueType>(m_serial) << 32 | static_cast<ByteCodeValueType>(local_index);

        StringSetTrie u8_trie { 0, false };
        StringSetTrie u16_trie { 0, false };

        for (auto const& str : strings) {
            Vector<u32> code_points;
            Utf8View utf8_view { str.bytes_as_string_view() };
            for (auto code_point : utf8_view)
                code_points.append(code_point);

            (void)u8_trie.insert(code_points.begin(), code_points.end(), true, [](auto&, auto) { return false; });

            auto utf16_string = Utf16String::from_utf32({ code_points.data(), code_points.size() });
            Vector<u32> u16_code_units;
            auto utf16_view = utf16_string.utf16_view();
            for (size_t i = 0; i < utf16_view.length_in_code_units(); i++) {
                auto code_unit = utf16_view.code_unit_at(i);
                u16_code_units.append(code_unit);
            }
            (void)u16_trie.insert(u16_code_units.begin(), u16_code_units.end(), true, [](auto&, auto) { return false; });
        }

        m_u8_tries.set(global_index, move(u8_trie));
        m_u16_tries.set(global_index, move(u16_trie));
        return global_index;
    }

    StringSetTrie const& get_u8_trie(ByteCodeValueType index) const
    {
        return m_u8_tries.get(index).value();
    }

    StringSetTrie const& get_u16_trie(ByteCodeValueType index) const
    {
        return m_u16_tries.get(index).value();
    }

    u32 m_serial { 0 };
    HashMap<ByteCodeValueType, StringSetTrie> m_u8_tries;
    HashMap<ByteCodeValueType, StringSetTrie> m_u16_tries;
};

struct ByteCodeBase {
    FlyString get_string(size_t index) const { return m_string_table.get(index); }
    auto const& string_table() const { return m_string_table; }

    auto get_u16_string(size_t index) const { return m_u16_string_table.get(index); }
    auto const& u16_string_table() const { return m_u16_string_table; }

    auto const& string_set_table() const { return m_string_set_table; }
    auto& string_set_table() { return m_string_set_table; }

    Optional<size_t> get_group_name_index(size_t group_index) const
    {
        return m_group_name_mappings.get(group_index);
    }

protected:
    StringTable<FlyString> m_string_table;
    StringTable<Utf16FlyString> m_u16_string_table;
    StringSetTable m_string_set_table;
    HashMap<size_t, size_t> m_group_name_mappings;
};

class REGEX_API ByteCode : public ByteCodeBase
    , public DisjointChunks<ByteCodeValueType> {
    using Base = DisjointChunks<ByteCodeValueType>;
    friend class FlatByteCode;

public:
    using Base::append;

    ByteCode()
    {
        ensure_opcodes_initialized();
    }

    ByteCode(ByteCode const&) = default;
    ByteCode(ByteCode&&) = default;

    ByteCode(Base&&) = delete;
    ByteCode(Base const&) = delete;

    ~ByteCode() = default;

    ByteCode& operator=(ByteCode const&) = default;
    ByteCode& operator=(ByteCode&&) = default;

    ByteCode& operator=(Base&& value) = delete;
    ByteCode& operator=(Base const& value) = delete;

    void extend(ByteCode&& other)
    {
        merge_string_tables_from({ &other, 1 });
        Base::extend(move(other));
    }

    void extend(ByteCode const& other)
    {
        merge_string_tables_from({ &other, 1 });
        Base::extend(other);
    }

    template<SameAs<Vector<ByteCodeValueType>> T>
    void extend(T other)
    {
        Base::append(move(other));
    }

    template<typename... Args>
    void empend(Args&&... args)
    {
        if (is_empty())
            Base::append({});
        Base::last_chunk().empend(forward<Args>(args)...);
    }
    template<typename T>
    void append(T&& value)
    {
        if (is_empty())
            Base::append({});
        Base::last_chunk().append(forward<T>(value));
    }
    template<typename T>
    void prepend(T&& value)
    {
        if (is_empty())
            return append(forward<T>(value));
        Base::first_chunk().prepend(forward<T>(value));
    }

    void append(Span<ByteCodeValueType const> value)
    {
        if (is_empty())
            Base::append({});
        auto& last = Base::last_chunk();
        last.ensure_capacity(value.size());
        for (auto v : value)
            last.unchecked_append(v);
    }

    void ensure_capacity(size_t capacity)
    {
        if (is_empty())
            Base::append({});
        Base::last_chunk().ensure_capacity(capacity);
    }

    void last_chunk() const = delete;
    void first_chunk() const = delete;

    void merge_string_tables_from(Span<ByteCode const> others)
    {
        for (auto const& other : others) {
            for (auto const& entry : other.m_string_table.m_table) {
                auto const result = m_string_table.m_inverse_table.set(entry.value, entry.key);
                if (result != HashSetResult::InsertedNewEntry) {
                    if (m_string_table.m_inverse_table.get(entry.value) == entry.key) // Already in inverse table.
                        continue;
                    dbgln("StringTable: Detected ID clash in string tables! ID {} seems to be reused", entry.value);
                    dbgln("Old: {}, New: {}", m_string_table.m_inverse_table.get(entry.value), entry.key);
                    VERIFY_NOT_REACHED();
                }
                m_string_table.m_table.set(entry.key, entry.value);
            }
            m_string_table.m_inverse_table.update(other.m_string_table.m_inverse_table);

            for (auto const& entry : other.m_u16_string_table.m_table) {
                auto const result = m_u16_string_table.m_inverse_table.set(entry.value, entry.key);
                if (result != HashSetResult::InsertedNewEntry) {
                    if (m_u16_string_table.m_inverse_table.get(entry.value) == entry.key) // Already in inverse table.
                        continue;
                    dbgln("StringTable: Detected ID clash in string tables! ID {} seems to be reused", entry.value);
                    dbgln("Old: {}, New: {}", m_u16_string_table.m_inverse_table.get(entry.value), entry.key);
                    VERIFY_NOT_REACHED();
                }
                m_u16_string_table.m_table.set(entry.key, entry.value);
            }
            m_u16_string_table.m_inverse_table.update(other.m_u16_string_table.m_inverse_table);

            for (auto const& entry : other.m_string_set_table.m_u8_tries) {
                m_string_set_table.m_u8_tries.set(entry.key, MUST(const_cast<StringSetTrie&>(entry.value).deep_copy()));
            }
            for (auto const& entry : other.m_string_set_table.m_u16_tries) {
                m_string_set_table.m_u16_tries.set(entry.key, MUST(const_cast<StringSetTrie&>(entry.value).deep_copy()));
            }

            for (auto const& mapping : other.m_group_name_mappings) {
                m_group_name_mappings.set(mapping.key, mapping.value);
            }
        }
    }

    void insert_bytecode_compare_values(Vector<CompareTypeAndValuePair>&& pairs)
    {
        Optimizer::append_character_class(*this, move(pairs));
    }

    void insert_bytecode_check_boundary(BoundaryCheckType type)
    {
        ByteCode bytecode;
        bytecode.empend((ByteCodeValueType)OpCodeId::CheckBoundary);
        bytecode.empend((ByteCodeValueType)type);

        extend(move(bytecode));
    }

    void insert_bytecode_clear_capture_group(size_t index)
    {
        empend(static_cast<ByteCodeValueType>(OpCodeId::ClearCaptureGroup));
        empend(index);
    }

    void insert_bytecode_compare_string(Utf16FlyString string)
    {
        empend(static_cast<ByteCodeValueType>(OpCodeId::Compare));
        empend(static_cast<u64>(1)); // number of arguments
        empend(static_cast<u64>(2)); // size of arguments
        empend(static_cast<ByteCodeValueType>(CharacterCompareType::String));
        auto index = m_u16_string_table.set(move(string));
        empend(index);
    }

    void insert_bytecode_group_capture_left(size_t capture_groups_count)
    {
        empend(static_cast<ByteCodeValueType>(OpCodeId::SaveLeftCaptureGroup));
        empend(capture_groups_count);
    }

    void insert_bytecode_group_capture_right(size_t capture_groups_count)
    {
        empend(static_cast<ByteCodeValueType>(OpCodeId::SaveRightCaptureGroup));
        empend(capture_groups_count);
    }

    void insert_bytecode_group_capture_right(size_t capture_groups_count, FlyString name)
    {
        empend(static_cast<ByteCodeValueType>(OpCodeId::SaveRightNamedCaptureGroup));
        auto name_string_index = m_string_table.set(move(name));
        empend(name_string_index);
        empend(capture_groups_count);

        m_group_name_mappings.set(capture_groups_count - 1, name_string_index);
    }

    void insert_bytecode_save_modifiers(FlagsUnderlyingType new_modifiers)
    {
        empend(static_cast<ByteCodeValueType>(OpCodeId::SaveModifiers));
        empend(static_cast<ByteCodeValueType>(new_modifiers));
    }

    void insert_bytecode_restore_modifiers()
    {
        empend(static_cast<ByteCodeValueType>(OpCodeId::RestoreModifiers));
    }

    enum class LookAroundType {
        LookAhead,
        LookBehind,
        NegatedLookAhead,
        NegatedLookBehind,
    };
    void insert_bytecode_lookaround(ByteCode&& lookaround_body, LookAroundType type, size_t match_length = 0, bool greedy_lookaround = true)
    {
        // FIXME: The save stack will grow infinitely with repeated failures
        //        as we do not discard that on failure (we don't necessarily know how many to pop with the current architecture).
        switch (type) {
        case LookAroundType::LookAhead: {
            // SAVE
            // FORKJUMP _BODY
            // POPSAVED
            // LABEL _BODY
            // REGEXP BODY
            // RESTORE
            empend((ByteCodeValueType)OpCodeId::Save);
            empend((ByteCodeValueType)OpCodeId::ForkJump);
            empend((ByteCodeValueType)1);
            empend((ByteCodeValueType)OpCodeId::PopSaved);
            extend(move(lookaround_body));
            empend((ByteCodeValueType)OpCodeId::Restore);
            return;
        }
        case LookAroundType::NegatedLookAhead: {
            // JUMP _A
            // LABEL _L
            // REGEXP BODY
            // FAIL
            // LABEL _A
            // SAVE
            // FORKJUMP _L
            // RESTORE
            auto body_length = lookaround_body.size();
            empend((ByteCodeValueType)OpCodeId::Jump);
            empend((ByteCodeValueType)body_length + 1); // JUMP to label _A
            extend(move(lookaround_body));
            empend((ByteCodeValueType)OpCodeId::FailForks);
            empend((ByteCodeValueType)OpCodeId::Save);
            empend((ByteCodeValueType)OpCodeId::ForkJump);
            empend((ByteCodeValueType) - (body_length + 4)); // JUMP to label _L
            empend((ByteCodeValueType)OpCodeId::Restore);
            return;
        }
        case LookAroundType::LookBehind: {
            // SAVE
            // SET_STEPBACK match_length(BODY)-1
            // LABEL _START
            // INC_STEPBACK
            // FORK_JUMP _BODY
            // CHECK_STEPBACK
            // JUMP _START
            // LABEL _BODY
            // REGEX BODY
            // CHECK_SAVED_POSITION
            // RESTORE
            auto body_length = lookaround_body.size();
            empend((ByteCodeValueType)OpCodeId::Save);
            empend((ByteCodeValueType)OpCodeId::SetStepBack);
            empend((ByteCodeValueType)match_length - 1);
            empend((ByteCodeValueType)OpCodeId::IncStepBack);
            empend((ByteCodeValueType)OpCodeId::ForkJump);
            empend((ByteCodeValueType)1 + 2); // JUMP to label _BODY
            empend((ByteCodeValueType)OpCodeId::CheckStepBack);
            empend((ByteCodeValueType)OpCodeId::Jump);
            empend((ByteCodeValueType)-6); // JUMP to label _START
            extend(move(lookaround_body));
            if (greedy_lookaround) {
                empend((ByteCodeValueType)OpCodeId::ForkJump);
                empend((ByteCodeValueType)(0 - 2 - body_length - 6));
            }
            empend((ByteCodeValueType)OpCodeId::CheckSavedPosition);
            empend((ByteCodeValueType)OpCodeId::Restore);
            return;
        }
        case LookAroundType::NegatedLookBehind: {
            // JUMP _A
            // LABEL _L
            // GOBACK match_length(BODY)
            // REGEXP BODY
            // FAIL
            // LABEL _A
            // SAVE
            // FORKJUMP _L
            // RESTORE
            auto body_length = lookaround_body.size();
            empend((ByteCodeValueType)OpCodeId::Jump);
            empend((ByteCodeValueType)body_length + 3); // JUMP to label _A
            empend((ByteCodeValueType)OpCodeId::GoBack);
            empend((ByteCodeValueType)match_length);
            extend(move(lookaround_body));
            empend((ByteCodeValueType)OpCodeId::FailForks);
            empend((ByteCodeValueType)OpCodeId::Save);
            empend((ByteCodeValueType)OpCodeId::ForkJump);
            empend((ByteCodeValueType) - (body_length + 6)); // JUMP to label _L
            empend((ByteCodeValueType)OpCodeId::Restore);
            return;
        }
        }

        VERIFY_NOT_REACHED();
    }

    void insert_bytecode_alternation(ByteCode&& left, ByteCode&& right)
    {

        // FORKJUMP _ALT
        // REGEXP ALT2
        // JUMP  _END
        // LABEL _ALT
        // REGEXP ALT1
        // LABEL _END

        // Optimisation: Eliminate extra work by unifying common pre-and-postfix exprs.
        Optimizer::append_alternation(*this, move(left), move(right));
    }

    template<Integral T>
    static void transform_bytecode_repetition_min_max(ByteCode& bytecode_to_repeat, T minimum, Optional<T> maximum, size_t min_repetition_mark_id, size_t max_repetition_mark_id, bool greedy = true)
    {
        if (!maximum.has_value()) {
            if (minimum == 0)
                return transform_bytecode_repetition_any(bytecode_to_repeat, greedy);
            if (minimum == 1)
                return transform_bytecode_repetition_min_one(bytecode_to_repeat, greedy);
        }

        if (minimum == 0 && maximum.has_value() && maximum.value() == 1) {
            return transform_bytecode_repetition_zero_or_one(bytecode_to_repeat, greedy);
        }

        ByteCode new_bytecode;
        new_bytecode.insert_bytecode_repetition_n(bytecode_to_repeat, minimum, min_repetition_mark_id);

        if (maximum.has_value()) {
            // (REPEAT REGEXP MIN)
            // LABEL _MAX_LOOP            |
            // FORK END                   |
            // CHECKPOINT (if min==0)     |
            // REGEXP                     |
            // FAILIFEMPTY (if min==0)    |
            // REPEAT _MAX_LOOP MAX-MIN   | if max > min
            // FORK END                   |
            // CHECKPOINT (if min==0)     |
            // REGEXP                     |
            // FAILIFEMPTY (if min==0)    |
            // LABEL END                  |
            // RESET _MAX_LOOP            |
            auto jump_kind = static_cast<ByteCodeValueType>(greedy ? OpCodeId::ForkStay : OpCodeId::ForkJump);
            if (maximum.value() > minimum) {
                new_bytecode.empend(jump_kind);
                new_bytecode.empend((ByteCodeValueType)0); // Placeholder for the jump target.
                auto pre_loop_fork_jump_index = new_bytecode.size();

                auto checkpoint1 = minimum == 0 ? s_next_checkpoint_serial_id++ : 0;
                if (minimum == 0) {
                    new_bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::Checkpoint));
                    new_bytecode.empend(static_cast<ByteCodeValueType>(checkpoint1));
                }

                new_bytecode.extend(bytecode_to_repeat);

                if (minimum == 0) {
                    new_bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::FailIfEmpty));
                    new_bytecode.empend(checkpoint1);
                }

                auto repetitions = maximum.value() - minimum;
                auto fork_jump_address = new_bytecode.size();
                if (repetitions > 1) {
                    auto repeated_bytecode_size = bytecode_to_repeat.size();
                    if (minimum == 0)
                        repeated_bytecode_size += 4; // Checkpoint + FailIfEmpty

                    new_bytecode.empend((ByteCodeValueType)OpCodeId::Repeat);
                    new_bytecode.empend(repeated_bytecode_size + 2);
                    new_bytecode.empend(static_cast<ByteCodeValueType>(repetitions - 1));
                    new_bytecode.empend(max_repetition_mark_id);
                    new_bytecode.empend(jump_kind);
                    new_bytecode.empend((ByteCodeValueType)0); // Placeholder for the jump target.
                    auto post_loop_fork_jump_index = new_bytecode.size();

                    auto checkpoint2 = minimum == 0 ? s_next_checkpoint_serial_id++ : 0;
                    if (minimum == 0) {
                        new_bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::Checkpoint));
                        new_bytecode.empend(static_cast<ByteCodeValueType>(checkpoint2));
                    }

                    new_bytecode.extend(bytecode_to_repeat);

                    if (minimum == 0) {
                        new_bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::FailIfEmpty));
                        new_bytecode.empend(checkpoint2);
                    }

                    fork_jump_address = new_bytecode.size();

                    new_bytecode[post_loop_fork_jump_index - 1] = (ByteCodeValueType)(fork_jump_address - post_loop_fork_jump_index);

                    new_bytecode.empend((ByteCodeValueType)OpCodeId::ResetRepeat);
                    new_bytecode.empend((ByteCodeValueType)max_repetition_mark_id);
                }
                new_bytecode[pre_loop_fork_jump_index - 1] = (ByteCodeValueType)(fork_jump_address - pre_loop_fork_jump_index);
            }
        } else {
            // no maximum value set, repeat finding if possible:
            // (REPEAT REGEXP MIN)
            // LABEL _START
            // CHECKPOINT _C
            // REGEXP
            // JUMP_NONEMPTY _C _START FORK

            // Note: This is only safe because REPEAT will leave one iteration outside (see repetition_n)
            auto checkpoint = s_next_checkpoint_serial_id++;
            new_bytecode.insert(new_bytecode.size() - bytecode_to_repeat.size(), (ByteCodeValueType)OpCodeId::Checkpoint);
            new_bytecode.insert(new_bytecode.size() - bytecode_to_repeat.size(), (ByteCodeValueType)checkpoint);

            auto jump_kind = static_cast<ByteCodeValueType>(greedy ? OpCodeId::ForkJump : OpCodeId::ForkStay);
            new_bytecode.empend((ByteCodeValueType)OpCodeId::JumpNonEmpty);
            new_bytecode.empend(-bytecode_to_repeat.size() - 4 - 2); // Jump to the last iteration
            new_bytecode.empend(checkpoint);                         // if _C is not empty.
            new_bytecode.empend(jump_kind);
        }

        bytecode_to_repeat = move(new_bytecode);
    }

    template<Integral T>
    void insert_bytecode_repetition_n(ByteCode& bytecode_to_repeat, T n, size_t repetition_mark_id)
    {
        // LABEL _LOOP
        // REGEXP
        // REPEAT _LOOP N-1
        // REGEXP
        if (n == 0)
            return;

        // Note: this bytecode layout allows callers to repeat the last REGEXP instruction without the
        // REPEAT instruction forcing another loop.
        extend(bytecode_to_repeat);

        if (n > 1) {
            empend(static_cast<ByteCodeValueType>(OpCodeId::Repeat));
            empend(bytecode_to_repeat.size());
            empend(static_cast<ByteCodeValueType>(n - 1));
            empend(repetition_mark_id);

            extend(bytecode_to_repeat);
        }
    }

    static void transform_bytecode_repetition_min_one(ByteCode& bytecode_to_repeat, bool greedy)
    {
        // LABEL _START = -bytecode_to_repeat.size()
        // CHECKPOINT _C
        // REGEXP
        // JUMP_NONEMPTY _C _START FORKSTAY (FORKJUMP -> Greedy)

        auto checkpoint = s_next_checkpoint_serial_id++;
        bytecode_to_repeat.prepend((ByteCodeValueType)checkpoint);
        bytecode_to_repeat.prepend((ByteCodeValueType)OpCodeId::Checkpoint);

        bytecode_to_repeat.empend((ByteCodeValueType)OpCodeId::JumpNonEmpty);
        bytecode_to_repeat.empend(-bytecode_to_repeat.size() - 3); // Jump to the _START label...
        bytecode_to_repeat.empend(checkpoint);                     // ...if _C is not empty

        if (greedy)
            bytecode_to_repeat.empend(static_cast<ByteCodeValueType>(OpCodeId::ForkJump));
        else
            bytecode_to_repeat.empend(static_cast<ByteCodeValueType>(OpCodeId::ForkStay));
    }

    static void transform_bytecode_repetition_any(ByteCode& bytecode_to_repeat, bool greedy)
    {
        // LABEL _START
        // FORKJUMP _END  (FORKSTAY -> Greedy)
        // CHECKPOINT _C
        // REGEXP
        // FAILIFEMPTY _C
        // JUMP_NONEMPTY _C _START JUMP
        // LABEL _END

        // LABEL _START = m_bytes.size();
        ByteCode bytecode;

        if (greedy)
            bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::ForkStay));
        else
            bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::ForkJump));

        bytecode.empend(bytecode_to_repeat.size() + 2 + 4 + 2); // Jump to the _END label

        auto checkpoint = s_next_checkpoint_serial_id++;
        bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::Checkpoint));
        bytecode.empend(static_cast<ByteCodeValueType>(checkpoint));

        bytecode.extend(bytecode_to_repeat);

        bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::FailIfEmpty));
        bytecode.empend(checkpoint);

        bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::JumpNonEmpty));
        bytecode.empend(-bytecode.size() - 3); // Jump(...) to the _START label...
        bytecode.empend(checkpoint);           // ...only if _C passes.
        bytecode.empend((ByteCodeValueType)OpCodeId::Jump);
        // LABEL _END = bytecode.size()

        bytecode_to_repeat = move(bytecode);
    }

    static void transform_bytecode_repetition_zero_or_one(ByteCode& bytecode_to_repeat, bool greedy)
    {
        // FORKJUMP _END (FORKSTAY -> Greedy)
        // CHECKPOINT _C
        // REGEXP
        // FAILIFEMPTY _C
        // LABEL _END
        ByteCode bytecode;

        if (greedy)
            bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::ForkStay));
        else
            bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::ForkJump));

        bytecode.empend(bytecode_to_repeat.size() + 4); // Jump to the _END label

        auto checkpoint = s_next_checkpoint_serial_id++;
        bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::Checkpoint));
        bytecode.empend(static_cast<ByteCodeValueType>(checkpoint));

        bytecode.extend(move(bytecode_to_repeat));

        bytecode.empend(static_cast<ByteCodeValueType>(OpCodeId::FailIfEmpty));
        bytecode.empend(checkpoint);
        // LABEL _END = bytecode.size()

        bytecode_to_repeat = move(bytecode);
    }

    OpCode<ByteCode>& get_opcode(MatchState& state) const;

    static void reset_checkpoint_serial_id() { s_next_checkpoint_serial_id = 0; }

private:
    void ensure_opcodes_initialized();
    ALWAYS_INLINE OpCode<ByteCode>& get_opcode_by_id(OpCodeId id) const;
    static OwnPtr<OpCode<ByteCode>> s_opcodes[(size_t)OpCodeId::Last + 1];
    static bool s_opcodes_initialized;
    static size_t s_next_checkpoint_serial_id;
};

class REGEX_API FlatByteCode : public ByteCodeBase {
public:
    static FlatByteCode from(ByteCode&& bytecode)
    {
        ensure_opcodes_initialized();
        FlatByteCode flat_bytecode;
        if (!bytecode.is_empty())
            flat_bytecode.m_data = move(static_cast<DisjointChunks<ByteCodeValueType>&>(bytecode).first_chunk());
        flat_bytecode.m_string_table = move(bytecode.m_string_table);
        flat_bytecode.m_u16_string_table = move(bytecode.m_u16_string_table);
        flat_bytecode.m_string_set_table = move(bytecode.m_string_set_table);
        flat_bytecode.m_group_name_mappings = move(bytecode.m_group_name_mappings);
        return flat_bytecode;
    }

    Span<ByteCodeValueType const> flat_data() const { return m_data.span(); }
    OpCode<FlatByteCode>& get_opcode(MatchState& state) const;
    auto& at(size_t index) { return m_data.data()[index]; }
    auto const& at(size_t index) const { return m_data.data()[index]; }
    auto& operator[](size_t index) { return m_data.data()[index]; }
    auto const& operator[](size_t index) const { return m_data.data()[index]; }
    auto size() const { return m_data.size(); }

    auto begin() const { return m_data.begin(); }
    auto end() const { return m_data.end(); }

private:
    static void ensure_opcodes_initialized();
    ALWAYS_INLINE OpCode<FlatByteCode>& get_opcode_by_id(OpCodeId id) const;
    static OwnPtr<OpCode<FlatByteCode>> s_opcodes[(size_t)OpCodeId::Last + 1];
    static bool s_opcodes_initialized;

    Vector<ByteCodeValueType> m_data;
};

#define ENUMERATE_EXECUTION_RESULTS                                                     \
    __ENUMERATE_EXECUTION_RESULT(Continue)                                              \
    __ENUMERATE_EXECUTION_RESULT(Fork_PrioHigh)                                         \
    __ENUMERATE_EXECUTION_RESULT(Fork_PrioLow)                                          \
    __ENUMERATE_EXECUTION_RESULT(Failed)                                                \
    __ENUMERATE_EXECUTION_RESULT(Failed_ExecuteLowPrioForks)                            \
    __ENUMERATE_EXECUTION_RESULT(Failed_ExecuteLowPrioForksButNoFurtherPossibleMatches) \
    __ENUMERATE_EXECUTION_RESULT(Succeeded)

enum class ExecutionResult : u8 {
#define __ENUMERATE_EXECUTION_RESULT(x) x,
    ENUMERATE_EXECUTION_RESULTS
#undef __ENUMERATE_EXECUTION_RESULT
};

StringView execution_result_name(ExecutionResult result);
StringView opcode_id_name(OpCodeId opcode_id);
StringView boundary_check_type_name(BoundaryCheckType);
StringView character_compare_type_name(CharacterCompareType result);
StringView character_class_name(CharClass ch_class);
StringView fork_if_condition_name(ForkIfCondition condition);

void save_string_position(MatchInput const& input, MatchState const& state);
bool restore_string_position(MatchInput const& input, MatchState& state);
void reverse_string_position(MatchState& state, RegexStringView view, size_t amount);
bool is_word_character(u32 code_point, bool case_insensitive, bool unicode_mode);

template<typename ByteCode>
class OpCode {
public:
    OpCode() = default;
    virtual ~OpCode() = default;

    virtual OpCodeId opcode_id() const = 0;
    virtual size_t size() const = 0;
    virtual ExecutionResult execute(MatchInput const& input, MatchState& state) const = 0;

    ALWAYS_INLINE ByteCodeValueType argument(size_t offset) const
    {
        return m_bytecode->at(state().instruction_position + 1 + offset);
    }

    ALWAYS_INLINE StringView name() const { return name(opcode_id()); }
    static StringView name(OpCodeId);

    ALWAYS_INLINE void set_state(MatchState const& state) { m_state = &state; }

    ALWAYS_INLINE void set_bytecode(ByteCode& bytecode) { m_bytecode = &bytecode; }

    ALWAYS_INLINE MatchState const& state() const { return *m_state; }

    ByteString to_byte_string() const
    {
        return ByteString::formatted("[{:#02X}] {}", (int)opcode_id(), name(opcode_id()));
    }

    virtual ByteString arguments_string() const = 0;

    ALWAYS_INLINE ByteCode const& bytecode() const { return *m_bytecode; }

protected:
    ByteCode* m_bytecode { nullptr };
    MatchState const* m_state { nullptr };
};

template<typename ByteCode>
class REGEX_API OpCode_SaveModifiers final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::SaveModifiers; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE FlagsUnderlyingType new_modifiers() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("new_modifiers={:#x}", new_modifiers()); }
};

template<typename ByteCode>
class REGEX_API OpCode_RestoreModifiers final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::RestoreModifiers; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_Exit final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::Exit; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_FailForks final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::FailForks; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_PopSaved final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::PopSaved; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_Save final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::Save; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_Restore final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::Restore; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_GoBack final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::GoBack; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t count() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("count={}", count()); }
};

template<typename ByteCode>
class REGEX_API OpCode_SetStepBack final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::SetStepBack; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE i64 step() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("step={}", step()); }
};

template<typename ByteCode>
class REGEX_API OpCode_IncStepBack final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::IncStepBack; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::formatted("inc step back"); }
};

template<typename ByteCode>
class REGEX_API OpCode_CheckStepBack final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::CheckStepBack; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::formatted("check step back"); }
};

template<typename ByteCode>
class REGEX_API OpCode_CheckSavedPosition final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::CheckSavedPosition; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::formatted("check saved back"); }
};

template<typename ByteCode>
class REGEX_API OpCode_Jump final : public OpCode<ByteCode> {

public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::Jump; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE ssize_t offset() const { return argument(0); }
    ByteString arguments_string() const override
    {
        return ByteString::formatted("offset={} [&{}]", offset(), state().instruction_position + size() + offset());
    }
};

template<typename ByteCode>
class REGEX_API OpCode_ForkJump : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::ForkJump; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE ssize_t offset() const { return argument(0); }
    ByteString arguments_string() const override
    {
        return ByteString::formatted("offset={} [&{}], sp: {}", offset(), state().instruction_position + size() + offset(), state().string_position);
    }
};

template<typename ByteCode>
class REGEX_API OpCode_ForkReplaceJump final : public OpCode_ForkJump<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;
    using OpCode_ForkJump<ByteCode>::offset;
    using OpCode_ForkJump<ByteCode>::size;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::ForkReplaceJump; }
};

template<typename ByteCode>
class REGEX_API OpCode_ForkStay : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::ForkStay; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE ssize_t offset() const { return argument(0); }
    ByteString arguments_string() const override
    {
        return ByteString::formatted("offset={} [&{}], sp: {}", offset(), state().instruction_position + size() + offset(), state().string_position);
    }
};

template<typename ByteCode>
class REGEX_API OpCode_ForkReplaceStay final : public OpCode_ForkStay<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;
    using OpCode_ForkStay<ByteCode>::offset;
    using OpCode_ForkStay<ByteCode>::size;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::ForkReplaceStay; }
};

template<typename ByteCode>
class REGEX_API OpCode_CheckBegin final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::CheckBegin; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_CheckEnd final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::CheckEnd; }
    ALWAYS_INLINE size_t size() const override { return 1; }
    ByteString arguments_string() const override { return ByteString::empty(); }
};

template<typename ByteCode>
class REGEX_API OpCode_CheckBoundary final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::CheckBoundary; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t arguments_count() const { return 1; }
    ALWAYS_INLINE BoundaryCheckType type() const { return static_cast<BoundaryCheckType>(argument(0)); }
    ByteString arguments_string() const override { return ByteString::formatted("kind={} ({})", (long unsigned int)argument(0), boundary_check_type_name(type())); }
};

template<typename ByteCode>
class REGEX_API OpCode_ClearCaptureGroup final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::ClearCaptureGroup; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t id() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("id={}", id()); }
};

template<typename ByteCode>
class REGEX_API OpCode_FailIfEmpty final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::FailIfEmpty; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t checkpoint() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("checkpoint={}", checkpoint()); }
};

template<typename ByteCode>
class REGEX_API OpCode_SaveLeftCaptureGroup final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::SaveLeftCaptureGroup; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t id() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("id={}", id()); }
};

template<typename ByteCode>
class REGEX_API OpCode_SaveRightCaptureGroup final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::SaveRightCaptureGroup; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t id() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("id={}", id()); }
};

template<typename ByteCode>
class REGEX_API OpCode_SaveRightNamedCaptureGroup final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::SaveRightNamedCaptureGroup; }
    ALWAYS_INLINE size_t size() const override { return 3; }
    ALWAYS_INLINE FlyString name() const { return bytecode().get_string(name_string_table_index()); }
    ALWAYS_INLINE size_t name_string_table_index() const { return argument(0); }
    ALWAYS_INLINE size_t length() const { return name().bytes_as_string_view().length(); }
    ALWAYS_INLINE size_t id() const { return argument(1); }
    ByteString arguments_string() const override
    {
        return ByteString::formatted("name_id={}, id={}", argument(0), id());
    }
};

template<typename ByteCode>
class REGEX_API OpCode_RSeekTo final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::RSeekTo; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ByteString arguments_string() const override
    {
        auto ch = argument(0);
        if (ch <= 0x7f)
            return ByteString::formatted("before '{}'", ch);
        return ByteString::formatted("before u+{:04x}", argument(0));
    }
};

template<typename ByteCode, bool IsSimple>
class REGEX_API CompareInternals : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;
    static bool matches_character_class(CharClass, u32, bool insensitive, bool unicode_mode);

    Vector<CompareTypeAndValuePair> flat_compares() const;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE static void compare_char(MatchInput const& input, MatchState& state, u32 ch1, bool inverse, bool& inverse_matched);
    ALWAYS_INLINE static bool compare_string(MatchInput const& input, MatchState& state, RegexStringView str, bool& had_zero_length_match);
    ALWAYS_INLINE static void compare_character_class(MatchInput const& input, MatchState& state, CharClass character_class, u32 ch, bool inverse, bool& inverse_matched);
    ALWAYS_INLINE static void compare_character_range(MatchInput const& input, MatchState& state, u32 from, u32 to, u32 ch, bool inverse, bool& inverse_matched);
    ALWAYS_INLINE static void compare_property(MatchInput const& input, MatchState& state, Unicode::Property property, bool inverse, bool is_double_negation, bool& inverse_matched);
    ALWAYS_INLINE static void compare_general_category(MatchInput const& input, MatchState& state, Unicode::GeneralCategory general_category, bool inverse, bool is_double_negation, bool& inverse_matched);
    ALWAYS_INLINE static void compare_script(MatchInput const& input, MatchState& state, Unicode::Script script, bool inverse, bool& inverse_matched);
    ALWAYS_INLINE static void compare_script_extension(MatchInput const& input, MatchState& state, Unicode::Script script, bool inverse, bool& inverse_matched);

    static ExecutionResult execute_impl(ByteCode const& bytecode, ByteCodeValueType const* data, size_t ip, MatchInput const& input, MatchState& state);
};

template<typename ByteCode>
class REGEX_API OpCode_Compare : public CompareInternals<ByteCode, false> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;
    using CompareInternals<ByteCode, false>::flat_compares;

    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::Compare; }
    ALWAYS_INLINE size_t size() const override { return arguments_size() + 3; }
    ALWAYS_INLINE size_t arguments_count() const { return argument(0); }
    ALWAYS_INLINE size_t arguments_size() const { return argument(1); }
    ByteString arguments_string() const override;
    Vector<ByteString> variable_arguments_to_byte_string(Optional<MatchInput const&> input = {}) const;
};

template<typename ByteCode>
class REGEX_API OpCode_CompareSimple final : public CompareInternals<ByteCode, true> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;
    using CompareInternals<ByteCode, true>::flat_compares;

    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::CompareSimple; }
    ALWAYS_INLINE size_t size() const override { return 2 + arguments_size(); } // CompareSimple <arg_size> <arg_type> <arg_value>*
    ALWAYS_INLINE size_t arguments_count() const { return 1; }
    ALWAYS_INLINE size_t arguments_size() const { return argument(0); }
    ByteString arguments_string() const override;
};

template<typename ByteCode>
class REGEX_API OpCode_Repeat : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::Repeat; }
    ALWAYS_INLINE size_t size() const override { return 4; }
    ALWAYS_INLINE size_t offset() const { return argument(0); }
    ALWAYS_INLINE u64 count() const { return argument(1); }
    ALWAYS_INLINE size_t id() const { return argument(2); }
    ByteString arguments_string() const override
    {
        auto reps = id() < state().repetition_marks.size() ? state().repetition_marks.at(id()) : 0;
        return ByteString::formatted("offset={} [&{}] count={} id={} rep={}, sp: {}",
            static_cast<ssize_t>(offset()),
            state().instruction_position - offset(),
            count() + 1,
            id(),
            reps + 1,
            state().string_position);
    }
};

template<typename ByteCode>
class REGEX_API OpCode_ResetRepeat : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::ResetRepeat; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t id() const { return argument(0); }
    ByteString arguments_string() const override
    {
        auto reps = id() < state().repetition_marks.size() ? state().repetition_marks.at(id()) : 0;
        return ByteString::formatted("id={} rep={}", id(), reps + 1);
    }
};

template<typename ByteCode>
class REGEX_API OpCode_Checkpoint final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::Checkpoint; }
    ALWAYS_INLINE size_t size() const override { return 2; }
    ALWAYS_INLINE size_t id() const { return argument(0); }
    ByteString arguments_string() const override { return ByteString::formatted("id={}", id()); }
};

template<typename ByteCode>
class REGEX_API OpCode_JumpNonEmpty final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::JumpNonEmpty; }
    ALWAYS_INLINE size_t size() const override { return 4; }
    ALWAYS_INLINE ssize_t offset() const { return argument(0); }
    ALWAYS_INLINE ssize_t checkpoint() const { return argument(1); }
    ALWAYS_INLINE OpCodeId form() const { return (OpCodeId)argument(2); }
    ByteString arguments_string() const override
    {
        return ByteString::formatted("{} offset={} [&{}], cp={}",
            opcode_id_name(form()),
            offset(), state().instruction_position + size() + offset(),
            checkpoint());
    }
};

template<typename ByteCode>
class REGEX_API OpCode_ForkIf final : public OpCode<ByteCode> {
public:
    using OpCode<ByteCode>::argument;
    using OpCode<ByteCode>::name;
    using OpCode<ByteCode>::state;
    using OpCode<ByteCode>::bytecode;

    ExecutionResult execute(MatchInput const& input, MatchState& state) const override;
    ALWAYS_INLINE OpCodeId opcode_id() const override { return OpCodeId::ForkIf; }
    ALWAYS_INLINE size_t size() const override { return 4; }
    ALWAYS_INLINE ssize_t offset() const { return argument(0); }
    ALWAYS_INLINE OpCodeId form() const { return (OpCodeId)argument(1); }
    ALWAYS_INLINE ForkIfCondition condition() const { return (ForkIfCondition)argument(2); }
    ByteString arguments_string() const override
    {
        return ByteString::formatted("{} {} offset={} [&{}]",
            opcode_id_name(form()),
            fork_if_condition_name(condition()),
            offset(), state().instruction_position + size() + offset());
    }
};

ALWAYS_INLINE OpCode<FlatByteCode>& FlatByteCode::get_opcode(regex::MatchState& state) const
{
    OpCodeId opcode_id;
    if (m_data.size() <= state.instruction_position)
        opcode_id = OpCodeId::Exit;
    else
        opcode_id = static_cast<OpCodeId>(m_data.data()[state.instruction_position]);

    if (opcode_id >= OpCodeId::First && opcode_id <= OpCodeId::Last) {
    } else {
        dbgln("Invalid OpCodeId requested: {} at {}", (u32)opcode_id, state.instruction_position);
        VERIFY_NOT_REACHED();
    }
    auto& opcode = get_opcode_by_id(opcode_id);
    opcode.set_state(state);
    return opcode;
}

ALWAYS_INLINE OpCode<FlatByteCode>& FlatByteCode::get_opcode_by_id(OpCodeId id) const
{
    if (id >= OpCodeId::First && id <= OpCodeId::Last) {
    } else {
        dbgln("Invalid OpCodeId requested: {}", (u32)id);
        VERIFY_NOT_REACHED();
    }

    auto& opcode = s_opcodes[(u32)id];
    opcode->set_bytecode(*const_cast<FlatByteCode*>(this));
    return *opcode;
}

ALWAYS_INLINE OpCode<ByteCode>& ByteCode::get_opcode(regex::MatchState& state) const
{
    OpCodeId opcode_id;
    if (auto opcode_ptr = static_cast<DisjointChunks<ByteCodeValueType> const&>(*this).find(state.instruction_position))
        opcode_id = (OpCodeId)*opcode_ptr;
    else
        opcode_id = OpCodeId::Exit;

    auto& opcode = get_opcode_by_id(opcode_id);
    opcode.set_state(state);
    return opcode;
}

ALWAYS_INLINE OpCode<ByteCode>& ByteCode::get_opcode_by_id(OpCodeId id) const
{
    VERIFY(id >= OpCodeId::First && id <= OpCodeId::Last);

    auto& opcode = s_opcodes[(u32)id];
    opcode->set_bytecode(*const_cast<ByteCode*>(this));
    return *opcode;
}

namespace Detail {

template<template<typename> class T, typename ByteCode>
struct Is {
    static bool is(OpCode<ByteCode> const& opcode) { return ::is<T<ByteCode>>(opcode); }
};

template<typename ByteCode>
struct Is<OpCode_FailForks, ByteCode> {
    static bool is(OpCode<ByteCode> const& opcode)
    {
        return opcode.opcode_id() == OpCodeId::FailForks;
    }
};

template<typename ByteCode>
struct Is<OpCode_Exit, ByteCode> {
    static bool is(OpCode<ByteCode> const& opcode)
    {
        return opcode.opcode_id() == OpCodeId::Exit;
    }
};

template<typename ByteCode>
struct Is<OpCode_Compare, ByteCode> {
    static bool is(OpCode<ByteCode> const& opcode)
    {
        return opcode.opcode_id() == OpCodeId::Compare;
    }
};

template<typename ByteCode>
struct Is<OpCode_SetStepBack, ByteCode> {
    static bool is(OpCode<ByteCode> const& opcode)
    {
        return opcode.opcode_id() == OpCodeId::SetStepBack;
    }
};

template<typename ByteCode>
struct Is<OpCode_IncStepBack, ByteCode> {
    static bool is(OpCode<ByteCode> const& opcode)
    {
        return opcode.opcode_id() == OpCodeId::IncStepBack;
    }
};

template<typename ByteCode>
struct Is<OpCode_CheckStepBack, ByteCode> {
    static bool is(OpCode<ByteCode> const& opcode)
    {
        return opcode.opcode_id() == OpCodeId::CheckStepBack;
    }
};

template<typename ByteCode>
struct Is<OpCode_CheckSavedPosition, ByteCode> {
    static bool is(OpCode<ByteCode> const& opcode)
    {
        return opcode.opcode_id() == OpCodeId::CheckSavedPosition;
    }
};

}

template<template<typename> class T, typename ByteCode>
bool is(OpCode<ByteCode> const& opcode) { return Detail::Is<T, ByteCode>::is(opcode); }

template<template<typename> class T, typename ByteCode>
ALWAYS_INLINE T<ByteCode> const& to(OpCode<ByteCode> const& opcode)
{
    return as<T<ByteCode>>(opcode);
}

template<template<typename> class T, typename ByteCode>
ALWAYS_INLINE T<ByteCode>* to(OpCode<ByteCode>* opcode)
{
    return as<T<ByteCode>>(opcode);
}

template<template<typename> class T, typename ByteCode>
ALWAYS_INLINE T<ByteCode> const* to(OpCode<ByteCode> const* opcode)
{
    return as<T<ByteCode>>(opcode);
}

template<template<typename> class T, typename ByteCode>
ALWAYS_INLINE T<ByteCode>& to(OpCode<ByteCode>& opcode)
{
    return as<T<ByteCode>>(opcode);
}

template<typename ByteCode>
StringView OpCode<ByteCode>::name(OpCodeId opcode_id)
{
    switch (opcode_id) {
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

// U+2028 LINE SEPARATOR
constexpr u32 const LineSeparator { 0x2028 };
// U+2029 PARAGRAPH SEPARATOR
constexpr u32 const ParagraphSeparator { 0x2029 };

inline void advance_string_position(MatchState& state, RegexStringView view, Optional<u32> code_point = {})
{
    ++state.string_position;

    if (view.unicode()) {
        if (!code_point.has_value() && (state.string_position_in_code_units < view.length_in_code_units()))
            code_point = view.code_point_at(state.string_position_in_code_units);
        if (code_point.has_value())
            state.string_position_in_code_units += view.length_of_code_point(*code_point);
    } else {
        ++state.string_position_in_code_units;
    }
}

inline void advance_string_position(MatchState& state, RegexStringView, RegexStringView advance_by)
{
    state.string_position += advance_by.length();
    state.string_position_in_code_units += advance_by.length_in_code_units();
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE ExecutionResult CompareInternals<ByteCode, IsSimple>::execute(MatchInput const& input, MatchState& state) const
{
    return execute_impl(bytecode(), bytecode().flat_data().data(), state.instruction_position, input, state);
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE void CompareInternals<ByteCode, IsSimple>::compare_char(MatchInput const& input, MatchState& state, u32 ch1, bool inverse, bool& inverse_matched)
{
    if (state.string_position == input.view.length())
        return;

    auto input_view = input.view.unicode()
        ? input.view.substring_view(state.string_position, 1).code_point_at(0)
        : input.view.unicode_aware_code_point_at(state.string_position_in_code_units);

    bool equal;
    if (state.current_options & AllFlags::Insensitive) {
        equal = Unicode::canonicalize(input_view, input.view.unicode()) == Unicode::canonicalize(ch1, input.view.unicode());
    } else {
        equal = input_view == ch1;
    }

    if (equal) {
        if (inverse)
            inverse_matched = true;
        else
            advance_string_position(state, input.view, ch1);
    }
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE bool CompareInternals<ByteCode, IsSimple>::compare_string(MatchInput const& input, MatchState& state, RegexStringView str, bool& had_zero_length_match)
{
    if (state.string_position + str.length() > input.view.length()) {
        if (str.is_empty()) {
            had_zero_length_match = true;
            return true;
        }
        return false;
    }

    if (str.length() == 0) {
        had_zero_length_match = true;
        return true;
    }

    if (str.length() == 1) {
        auto inverse_matched = false;
        compare_char(input, state, str.code_point_at(0), false, inverse_matched);
        return !inverse_matched;
    }

    auto subject = input.view.substring_view(state.string_position, str.length());
    bool equals;
    if (state.current_options & AllFlags::Insensitive)
        equals = subject.equals_ignoring_case(str, input.view.unicode());
    else
        equals = subject.equals(str);

    if (equals)
        advance_string_position(state, input.view, str);

    return equals;
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE void CompareInternals<ByteCode, IsSimple>::compare_character_class(MatchInput const& input, MatchState& state, CharClass character_class, u32 ch, bool inverse, bool& inverse_matched)
{
    if (matches_character_class(character_class, ch, state.current_options & AllFlags::Insensitive, input.view.unicode())) {
        if (inverse)
            inverse_matched = true;
        else
            advance_string_position(state, input.view, ch);
    }
}

template<typename ByteCode, bool IsSimple>
bool CompareInternals<ByteCode, IsSimple>::matches_character_class(CharClass character_class, u32 ch, bool insensitive, bool unicode_mode)
{
    constexpr auto is_space_or_line_terminator = [](u32 code_point) {
        if ((code_point == 0x0a) || (code_point == 0x0d) || (code_point == 0x2028) || (code_point == 0x2029))
            return true;
        if ((code_point == 0x09) || (code_point == 0x0b) || (code_point == 0x0c) || (code_point == 0xfeff))
            return true;
        return Unicode::code_point_has_space_separator_general_category(code_point);
    };

    switch (character_class) {
    case CharClass::Alnum:
        return is_ascii_alphanumeric(ch);
    case CharClass::Alpha:
        return is_ascii_alpha(ch);
    case CharClass::Blank:
        return is_ascii_blank(ch);
    case CharClass::Cntrl:
        return is_ascii_control(ch);
    case CharClass::Digit:
        return is_ascii_digit(ch);
    case CharClass::Graph:
        return is_ascii_graphical(ch);
    case CharClass::Lower:
        return is_ascii_lower_alpha(ch) || (insensitive && is_ascii_upper_alpha(ch));
    case CharClass::Print:
        return is_ascii_printable(ch);
    case CharClass::Punct:
        return is_ascii_punctuation(ch);
    case CharClass::Space:
        return is_space_or_line_terminator(ch);
    case CharClass::Upper:
        return is_ascii_upper_alpha(ch) || (insensitive && is_ascii_lower_alpha(ch));
    case CharClass::Word:
        return is_word_character(ch, insensitive, unicode_mode);
    case CharClass::Xdigit:
        return is_ascii_hex_digit(ch);
    }

    VERIFY_NOT_REACHED();
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE void CompareInternals<ByteCode, IsSimple>::compare_character_range(MatchInput const& input, MatchState& state, u32 from, u32 to, u32 ch, bool inverse, bool& inverse_matched)
{
    bool matched = false;
    if (state.current_options & AllFlags::Insensitive) {
        matched = Unicode::code_point_matches_range_ignoring_case(ch, from, to, input.view.unicode());
    } else {
        matched = (ch >= from && ch <= to);
    }

    if (matched) {
        if (inverse)
            inverse_matched = true;
        else
            advance_string_position(state, input.view, ch);
    }
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE void CompareInternals<ByteCode, IsSimple>::compare_property(MatchInput const& input, MatchState& state, Unicode::Property property, bool inverse, bool is_double_negation, bool& inverse_matched)
{
    if (state.string_position == input.view.length())
        return;

    u32 code_point = input.view.code_point_at(state.string_position_in_code_units);
    bool case_insensitive = (state.current_options & AllFlags::Insensitive) && input.view.unicode();
    bool is_unicode_sets_mode = state.current_options.has_flag_set(AllFlags::UnicodeSets);

    if ((inverse || is_double_negation) && case_insensitive && !is_unicode_sets_mode) {
        bool any_variant_lacks_property = false;
        Unicode::for_each_case_folded_code_point(code_point, [&](u32 variant) {
            if (!Unicode::code_point_has_property(variant, property)) {
                any_variant_lacks_property = true;
                return IterationDecision::Break;
            }
            return IterationDecision::Continue;
        });

        if (is_double_negation) {
            if (any_variant_lacks_property)
                return;
            advance_string_position(state, input.view, code_point);
        } else if (!any_variant_lacks_property) {
            inverse_matched = true;
            return;
        }
    } else {
        auto case_sensitivity = case_insensitive && (is_unicode_sets_mode || !inverse) ? CaseSensitivity::CaseInsensitive : CaseSensitivity::CaseSensitive;
        if (Unicode::code_point_has_property(code_point, property, case_sensitivity)) {
            if (inverse)
                inverse_matched = true;
            else
                advance_string_position(state, input.view, code_point);
        }
    }
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE void CompareInternals<ByteCode, IsSimple>::compare_general_category(MatchInput const& input, MatchState& state, Unicode::GeneralCategory general_category, bool inverse, bool is_double_negation, bool& inverse_matched)
{
    if (state.string_position == input.view.length())
        return;

    u32 code_point = input.view.code_point_at(state.string_position_in_code_units);
    bool case_insensitive = (state.current_options & AllFlags::Insensitive) && input.view.unicode();
    bool is_unicode_sets_mode = state.current_options.has_flag_set(AllFlags::UnicodeSets);

    if ((inverse || is_double_negation) && case_insensitive && !is_unicode_sets_mode) {
        bool any_variant_lacks_category = false;
        Unicode::for_each_case_folded_code_point(code_point, [&](u32 variant) {
            if (!Unicode::code_point_has_general_category(variant, general_category)) {
                any_variant_lacks_category = true;
                return IterationDecision::Break;
            }
            return IterationDecision::Continue;
        });

        if (is_double_negation) {
            if (any_variant_lacks_category)
                return;
            advance_string_position(state, input.view, code_point);
        } else if (!any_variant_lacks_category) {
            inverse_matched = true;
            return;
        }
    } else {
        auto case_sensitivity = case_insensitive && (is_unicode_sets_mode || !inverse) ? CaseSensitivity::CaseInsensitive : CaseSensitivity::CaseSensitive;
        if (Unicode::code_point_has_general_category(code_point, general_category, case_sensitivity)) {
            if (inverse)
                inverse_matched = true;
            else
                advance_string_position(state, input.view, code_point);
        }
    }
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE void CompareInternals<ByteCode, IsSimple>::compare_script(MatchInput const& input, MatchState& state, Unicode::Script script, bool inverse, bool& inverse_matched)
{
    if (state.string_position == input.view.length())
        return;

    u32 code_point = input.view.code_point_at(state.string_position_in_code_units);
    bool equal = Unicode::code_point_has_script(code_point, script);

    if (equal) {
        if (inverse)
            inverse_matched = true;
        else
            advance_string_position(state, input.view, code_point);
    }
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE void CompareInternals<ByteCode, IsSimple>::compare_script_extension(MatchInput const& input, MatchState& state, Unicode::Script script, bool inverse, bool& inverse_matched)
{
    if (state.string_position == input.view.length())
        return;

    u32 code_point = input.view.code_point_at(state.string_position_in_code_units);
    bool equal = Unicode::code_point_has_script_extension(code_point, script);

    if (equal) {
        if (inverse)
            inverse_matched = true;
        else
            advance_string_position(state, input.view, code_point);
    }
}

template<typename ByteCode, bool IsSimple>
ALWAYS_INLINE ExecutionResult CompareInternals<ByteCode, IsSimple>::execute_impl(ByteCode const& bytecode, ByteCodeValueType const* data, size_t ip, MatchInput const& input, MatchState& state)
{
    auto const argument_count = IsSimple ? 1 : data[ip + 1];
    auto has_single_argument = argument_count == 1;

    bool inverse { false };
    bool temporary_inverse { false };
    bool reset_temp_inverse { false };
    struct DisjunctionState {
        bool active { false };
        bool is_conjunction { false };
        bool is_subtraction { false };
        bool is_and_operation { false };
        bool fail { false };
        bool inverse_matched { false };
        size_t subtraction_operand_index { 0 };
        size_t initial_position;
        size_t initial_code_unit_position;
        Optional<size_t> last_accepted_position {};
        Optional<size_t> last_accepted_code_unit_position {};
    };

    Vector<DisjunctionState, 4> disjunction_states;
    disjunction_states.unchecked_empend();

    auto current_disjunction_state = [&]() -> DisjunctionState& { return disjunction_states.last(); };

    auto current_inversion_state = [&]() -> bool {
        if constexpr (IsSimple)
            return false;
        else
            return temporary_inverse ^ inverse;
    };

    size_t string_position = state.string_position;
    bool inverse_matched { false };
    bool had_zero_length_match { false };

    state.string_position_before_match = state.string_position;

    bool has_string_set = false;
    bool string_set_matched = false;
    size_t best_match_position = state.string_position;
    size_t best_match_position_in_code_units = state.string_position_in_code_units;

    size_t offset { ip + (IsSimple ? 2 : 3) };
    CharacterCompareType last_compare_type = CharacterCompareType::Undefined;

    for (size_t i = 0; i < argument_count; ++i) {
        if (state.string_position > string_position)
            break;

        if (has_string_set) {
            state.string_position = string_position;
            state.string_position_in_code_units = current_disjunction_state().initial_code_unit_position;
        }

        auto compare_type = (CharacterCompareType)data[offset++];

        if constexpr (!IsSimple) {
            if (reset_temp_inverse) {
                reset_temp_inverse = false;
                if (compare_type != CharacterCompareType::Property || last_compare_type != CharacterCompareType::StringSet) {
                    temporary_inverse = false;
                }
            } else {
                reset_temp_inverse = true;
            }

            last_compare_type = compare_type;
        }

        switch (compare_type) {
        case CharacterCompareType::Inverse:
            inverse = !inverse;
            continue;
        case CharacterCompareType::TemporaryInverse:
            VERIFY(!IsSimple);
            VERIFY(i != argument_count - 1);

            temporary_inverse = true;
            reset_temp_inverse = false;
            continue;
        case CharacterCompareType::Char: {
            u32 ch = data[offset++];

            if (input.view.length() <= state.string_position)
                return ExecutionResult::Failed_ExecuteLowPrioForks;

            compare_char(input, state, ch, current_inversion_state(), inverse_matched);
            break;
        }
        case CharacterCompareType::AnyChar: {
            if (input.view.length() <= state.string_position)
                return ExecutionResult::Failed_ExecuteLowPrioForks;

            auto input_view = input.view.substring_view(state.string_position, 1).code_point_at(0);
            auto is_equivalent_to_newline = input_view == '\n'
                || (state.current_options.has_flag_set(AllFlags::Internal_ECMA262DotSemantics)
                        ? (input_view == '\r' || input_view == LineSeparator || input_view == ParagraphSeparator)
                        : false);

            if (!is_equivalent_to_newline || (state.current_options.has_flag_set(AllFlags::SingleLine) && state.current_options.has_flag_set(AllFlags::Internal_ConsiderNewline))) {
                if (current_inversion_state())
                    inverse_matched = true;
                else
                    advance_string_position(state, input.view, input_view);
            }
            break;
        }
        case CharacterCompareType::String: {
            VERIFY(!current_inversion_state());

            auto string_index = data[offset++];
            auto string = bytecode.get_u16_string(string_index);

            if (input.view.unicode()) {
                if (input.view.length() < state.string_position + string.length_in_code_points())
                    return ExecutionResult::Failed_ExecuteLowPrioForks;
            } else {
                if (input.view.length() < state.string_position_in_code_units + string.length_in_code_units())
                    return ExecutionResult::Failed_ExecuteLowPrioForks;
            }

            auto view = RegexStringView(string);
            view.set_unicode(input.view.unicode());
            if (compare_string(input, state, view, had_zero_length_match)) {
                if (current_inversion_state())
                    inverse_matched = true;
            }
            break;
        }
        case CharacterCompareType::CharClass: {
            if (input.view.length_in_code_units() <= state.string_position_in_code_units)
                return ExecutionResult::Failed_ExecuteLowPrioForks;

            auto character_class = (CharClass)data[offset++];
            auto ch = input.view.unicode_aware_code_point_at(state.string_position_in_code_units);

            compare_character_class(input, state, character_class, ch, current_inversion_state(), inverse_matched);
            break;
        }
        case CharacterCompareType::LookupTable: {
            if (input.view.length() <= state.string_position)
                return ExecutionResult::Failed_ExecuteLowPrioForks;

            auto count_sensitive = data[offset++];
            auto count_insensitive = data[offset++];
            auto sensitive_range_data = bytecode.flat_data().slice(offset, count_sensitive);
            offset += count_sensitive;
            auto insensitive_range_data = bytecode.flat_data().slice(offset, count_insensitive);
            offset += count_insensitive;

            bool const insensitive = state.current_options & AllFlags::Insensitive;
            auto ch = input.view.unicode_aware_code_point_at(state.string_position_in_code_units);

            if (insensitive)
                ch = to_ascii_lowercase(ch);

            auto const ranges = insensitive && !insensitive_range_data.is_empty() ? insensitive_range_data : sensitive_range_data;
            auto const* matching_range = binary_search(ranges, ch, nullptr, [](auto needle, CharRange range) {
                if (needle >= range.from && needle <= range.to)
                    return 0;
                if (needle > range.to)
                    return 1;
                return -1;
            });

            if (matching_range) {
                if (current_inversion_state())
                    inverse_matched = true;
                else
                    advance_string_position(state, input.view, ch);
            }
            break;
        }
        case CharacterCompareType::CharRange: {
            if (input.view.length() <= state.string_position)
                return ExecutionResult::Failed_ExecuteLowPrioForks;

            auto value = (CharRange)data[offset++];

            auto from = value.from;
            auto to = value.to;
            auto ch = input.view.unicode_aware_code_point_at(state.string_position_in_code_units);

            compare_character_range(input, state, from, to, ch, current_inversion_state(), inverse_matched);
            break;
        }
        case CharacterCompareType::Reference: {
            auto reference_number = ((size_t)data[offset++]) - 1;
            if (input.match_index >= state.capture_group_matches_size()) {
                had_zero_length_match = true;
                if (current_inversion_state())
                    inverse_matched = true;
                break;
            }

            auto groups = state.capture_group_matches(input.match_index);

            if (groups.size() <= reference_number) {
                had_zero_length_match = true;
                if (current_inversion_state())
                    inverse_matched = true;
                break;
            }

            auto str = groups.at(reference_number).view;

            if (input.view.length() < state.string_position + str.length())
                return ExecutionResult::Failed_ExecuteLowPrioForks;

            if (compare_string(input, state, str, had_zero_length_match)) {
                if (current_inversion_state())
                    inverse_matched = true;
            }
            break;
        }
        case CharacterCompareType::NamedReference: {
            auto reference_number = ((size_t)data[offset++]) - 1;

            if (input.match_index >= state.capture_group_matches_size()) {
                had_zero_length_match = true;
                if (current_inversion_state())
                    inverse_matched = true;
                break;
            }

            auto groups = state.capture_group_matches(input.match_index);

            if (groups.size() <= reference_number) {
                had_zero_length_match = true;
                if (current_inversion_state())
                    inverse_matched = true;
                break;
            }

            RegexStringView str {};

            auto reference_name_index = bytecode.get_group_name_index(reference_number);

            if (reference_name_index.has_value()) {
                auto target_name_string = bytecode.get_string(reference_name_index.value());

                for (size_t i = 0; i < groups.size(); ++i) {
                    if (groups[i].view.is_null())
                        continue;

                    auto group_name_index = bytecode.get_group_name_index(i);

                    if (group_name_index.has_value()) {
                        auto group_name_string = bytecode.get_string(group_name_index.value());

                        if (group_name_string == target_name_string) {
                            str = groups[i].view;
                            break;
                        }
                    }
                }
            }

            if (input.view.length() < state.string_position + str.length()) {
                return ExecutionResult::Failed_ExecuteLowPrioForks;
            }

            if (compare_string(input, state, str, had_zero_length_match)) {
                if (current_inversion_state())
                    inverse_matched = true;
            }
            break;
        }
        case CharacterCompareType::Property: {
            auto property = static_cast<Unicode::Property>(data[offset++]);
            compare_property(input, state, property, current_inversion_state(), temporary_inverse && inverse, inverse_matched);
            break;
        }
        case CharacterCompareType::GeneralCategory: {
            auto general_category = static_cast<Unicode::GeneralCategory>(data[offset++]);
            compare_general_category(input, state, general_category, current_inversion_state(), temporary_inverse && inverse, inverse_matched);
            break;
        }
        case CharacterCompareType::Script: {
            auto script = static_cast<Unicode::Script>(data[offset++]);
            compare_script(input, state, script, current_inversion_state(), inverse_matched);
            break;
        }
        case CharacterCompareType::ScriptExtension: {
            auto script = static_cast<Unicode::Script>(data[offset++]);
            compare_script_extension(input, state, script, current_inversion_state(), inverse_matched);
            break;
        }
        case CharacterCompareType::StringSet: {
            has_string_set = true;
            auto string_set_index = data[offset++];

            bool matched = false;
            size_t longest_match_length = 0;

            auto find_longest_match = [&](auto const& view, auto const& trie) {
                auto const* current = &trie;
                size_t current_code_unit_offset = state.string_position_in_code_units;

                if (current->has_metadata() && current->metadata_value()) {
                    matched = true;
                    longest_match_length = 0;
                }

                while (true) {
                    u32 value;

                    if constexpr (IsSame<decltype(view), Utf16View const&>) {
                        if (current_code_unit_offset >= view.length_in_code_units())
                            break;
                        value = view.code_unit_at(current_code_unit_offset);
                    } else {
                        if (current_code_unit_offset >= input.view.length_in_code_units())
                            break;
                        value = input.view.code_point_at(current_code_unit_offset);
                    }

                    if (state.current_options & AllFlags::Insensitive) {
                        bool found_child = false;
                        for (auto const& [key, child] : current->children()) {
                            if (Unicode::canonicalize(key, input.view.unicode()) == Unicode::canonicalize(value, input.view.unicode())) {
                                current = static_cast<StringSetTrie const*>(child.ptr());
                                current_code_unit_offset++;
                                found_child = true;
                                break;
                            }
                        }
                        if (!found_child)
                            break;
                    } else {
                        auto it = current->children().find(value);
                        if (it == current->children().end())
                            break;

                        current = static_cast<StringSetTrie const*>(it->value.ptr());
                        current_code_unit_offset++;
                    }

                    auto is_terminal = current->has_metadata() && current->metadata_value();
                    if (is_terminal) {
                        size_t match_length_in_code_points;
                        if constexpr (IsSame<decltype(view), Utf16View const&>) {
                            size_t code_points = 0;
                            for (size_t i = state.string_position_in_code_units; i < current_code_unit_offset;) {
                                auto code_point = view.code_point_at(i);
                                i += code_point >= 0x10000 ? 2 : 1;
                                code_points++;
                            }
                            match_length_in_code_points = code_points;
                        } else {
                            size_t code_points = 0;
                            for (size_t i = state.string_position_in_code_units; i < current_code_unit_offset;) {
                                auto code_point = input.view.code_point_at(i);
                                if (code_point <= 0x7F)
                                    i += 1;
                                else if (code_point <= 0x7FF)
                                    i += 2;
                                else if (code_point <= 0xFFFF)
                                    i += 3;
                                else
                                    i += 4;
                                code_points++;
                            }
                            match_length_in_code_points = code_points;
                        }

                        if (match_length_in_code_points > longest_match_length) {
                            matched = true;
                            longest_match_length = match_length_in_code_points;
                        }
                    }
                }
            };

            if (input.view.u16_view().is_null()) {
                auto const& trie = bytecode.string_set_table().get_u8_trie(string_set_index);
                StringView view;
                find_longest_match(view, trie);
            } else {
                auto const& view = input.view.u16_view();
                auto const& trie = bytecode.string_set_table().get_u16_trie(string_set_index);
                find_longest_match(view, trie);
            }

            if (matched) {
                if (longest_match_length == 0)
                    had_zero_length_match = true;
                if (current_inversion_state()) {
                    inverse_matched = true;
                } else {
                    state.string_position += longest_match_length;
                    if (input.view.unicode()) {
                        state.string_position_in_code_units = input.view.code_unit_offset_of(state.string_position);
                    } else {
                        state.string_position_in_code_units = state.string_position;
                    }
                }
            }
            break;
        }
        case CharacterCompareType::And:
            VERIFY(!IsSimple);
            if constexpr (!IsSimple) {
                disjunction_states.append({
                    .active = true,
                    .is_conjunction = current_inversion_state(),
                    .is_and_operation = true,
                    .fail = current_inversion_state(),
                    .inverse_matched = current_inversion_state(),
                    .initial_position = state.string_position,
                    .initial_code_unit_position = state.string_position_in_code_units,
                });
            }
            continue;
        case CharacterCompareType::Subtract:
            VERIFY(!IsSimple);
            if constexpr (!IsSimple) {
                disjunction_states.append({
                    .active = true,
                    .is_conjunction = true,
                    .is_subtraction = true,
                    .fail = true,
                    .inverse_matched = false,
                    .initial_position = state.string_position,
                    .initial_code_unit_position = state.string_position_in_code_units,
                });
            }
            continue;
        case CharacterCompareType::Or:
            VERIFY(!IsSimple);
            if constexpr (!IsSimple) {
                disjunction_states.append({
                    .active = true,
                    .is_conjunction = !current_inversion_state(),
                    .fail = !current_inversion_state(),
                    .inverse_matched = !current_inversion_state(),
                    .initial_position = state.string_position,
                    .initial_code_unit_position = state.string_position_in_code_units,
                });
            }
            continue;
        case CharacterCompareType::EndAndOr: {
            VERIFY(!IsSimple);
            if constexpr (!IsSimple) {
                auto disjunction_state = disjunction_states.take_last();
                if (!disjunction_state.fail) {
                    state.string_position = disjunction_state.last_accepted_position.value_or(disjunction_state.initial_position);
                    state.string_position_in_code_units = disjunction_state.last_accepted_code_unit_position.value_or(disjunction_state.initial_code_unit_position);
                } else if (has_string_set) {
                    string_set_matched = false;
                    best_match_position = disjunction_state.initial_position;
                    best_match_position_in_code_units = disjunction_state.initial_code_unit_position;
                }
                inverse_matched = disjunction_state.inverse_matched || disjunction_state.fail;
            }
            break;
        }
        default:
            warnln("Undefined comparison: {}", (int)compare_type);
            VERIFY_NOT_REACHED();
            break;
        }

        if constexpr (!IsSimple) {
            auto& new_disjunction_state = current_disjunction_state();
            if (current_inversion_state() && (!inverse || new_disjunction_state.active) && !inverse_matched) {
                advance_string_position(state, input.view);
                inverse_matched = true;
            }
        }

        if (has_string_set && state.string_position > best_match_position) {
            best_match_position = state.string_position;
            best_match_position_in_code_units = state.string_position_in_code_units;
            string_set_matched = true;
        }

        if constexpr (!IsSimple) {
            auto& new_disjunction_state = current_disjunction_state();
            if (!has_single_argument && new_disjunction_state.active) {
                auto failed = (!had_zero_length_match && string_position == state.string_position) || state.string_position > input.view.length();

                if (!failed && new_disjunction_state.is_and_operation
                    && new_disjunction_state.last_accepted_position.has_value()
                    && new_disjunction_state.last_accepted_position.value() != state.string_position) {

                    failed = true;
                }

                if (!failed) {
                    new_disjunction_state.last_accepted_position = state.string_position;
                    new_disjunction_state.last_accepted_code_unit_position = state.string_position_in_code_units;
                    new_disjunction_state.inverse_matched |= inverse_matched;
                }

                if (new_disjunction_state.is_subtraction) {
                    if (new_disjunction_state.subtraction_operand_index == 0) {
                        new_disjunction_state.fail = failed && new_disjunction_state.fail;
                    } else if (!failed && (!has_string_set || state.string_position >= best_match_position)) {
                        new_disjunction_state.fail = true;
                    }
                    new_disjunction_state.subtraction_operand_index++;
                } else if (new_disjunction_state.is_conjunction) {
                    new_disjunction_state.fail = failed && new_disjunction_state.fail;
                } else {
                    new_disjunction_state.fail = failed || new_disjunction_state.fail;
                }

                state.string_position = new_disjunction_state.initial_position;
                state.string_position_in_code_units = new_disjunction_state.initial_code_unit_position;
                inverse_matched = false;
            }
        }
    }

    if constexpr (!IsSimple) {
        if (!has_single_argument) {
            auto& new_disjunction_state = current_disjunction_state();
            if (new_disjunction_state.active && !new_disjunction_state.fail) {
                state.string_position = new_disjunction_state.last_accepted_position.value_or(new_disjunction_state.initial_position);
                state.string_position_in_code_units = new_disjunction_state.last_accepted_code_unit_position.value_or(new_disjunction_state.initial_code_unit_position);
            }
        }
    }

    if (has_string_set && string_set_matched) {
        if (has_single_argument || best_match_position > string_position) {
            state.string_position = best_match_position;
            state.string_position_in_code_units = best_match_position_in_code_units;
        }
    }

    if (current_inversion_state() && !inverse_matched && state.string_position == string_position)
        advance_string_position(state, input.view);

    if ((!had_zero_length_match && string_position == state.string_position) || state.string_position > input.view.length())
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    return ExecutionResult::Continue;
}

}
