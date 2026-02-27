/*
 * Copyright (c) 2020, Emanuel Sprung <emanuel.sprung@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/BinarySearch.h>
#include <AK/BumpAllocator.h>
#include <AK/ByteString.h>
#include <AK/Debug.h>
#include <AK/StringBuilder.h>
#include <LibRegex/RegexMatcher.h>
#include <LibRegex/RegexParser.h>
#include <LibUnicode/CharacterTypes.h>

#if REGEX_DEBUG
#    include <LibRegex/RegexDebug.h>
#endif

namespace regex {

#if REGEX_DEBUG
static RegexDebug<FlatByteCode> s_regex_dbg(stderr);
#endif

template<class Parser>
regex::Parser::Result Regex<Parser>::parse_pattern(StringView pattern, typename ParserTraits<Parser>::OptionsType regex_options)
{
    regex::Lexer lexer(pattern);

    Parser parser(lexer, regex_options);
    return parser.parse();
}

template<typename Parser>
struct CacheKey {
    ByteString pattern;
    typename ParserTraits<Parser>::OptionsType options;

    bool operator==(CacheKey const& other) const
    {
        return pattern == other.pattern && options.value() == other.options.value();
    }
};
template<class Parser>
static OrderedHashMap<CacheKey<Parser>, regex::Parser::Result> s_parser_cache;

template<class Parser>
static size_t s_cached_bytecode_size = 0;

static constexpr auto MaxRegexCachedBytecodeSize = 1 * MiB;

template<class Parser>
static void cache_parse_result(regex::Parser::Result const& result, CacheKey<Parser> const& key)
{
    auto bytecode_size = result.bytecode.visit([](auto& bytecode) { return bytecode.size() * sizeof(ByteCodeValueType); });
    if (bytecode_size > MaxRegexCachedBytecodeSize)
        return;

    while (bytecode_size + s_cached_bytecode_size<Parser> > MaxRegexCachedBytecodeSize)
        s_cached_bytecode_size<Parser> -= s_parser_cache<Parser>.take_first().bytecode.visit([](auto& bytecode) { return bytecode.size() * sizeof(ByteCodeValueType); });

    s_parser_cache<Parser>.set(key, result);
    s_cached_bytecode_size<Parser> += bytecode_size;
}

template<class Parser>
Regex<Parser>::Regex(ByteString pattern, typename ParserTraits<Parser>::OptionsType regex_options)
    : pattern_value(move(pattern))
    , parser_result(ByteCode {})
{
    if (auto cache_entry = s_parser_cache<Parser>.get({ pattern_value, regex_options }); cache_entry.has_value()) {
        parser_result = cache_entry.value();
    } else {
        regex::Lexer lexer(pattern_value);

        Parser parser(lexer, regex_options);
        parser_result = parser.parse();
        parser_result.bytecode.template get<ByteCode>().flatten();

        run_optimization_passes();

        if (parser_result.error == regex::Error::NoError)
            cache_parse_result<Parser>(parser_result, { pattern_value, regex_options });
    }

    if (parser_result.error == regex::Error::NoError)
        matcher = make<Matcher<Parser>>(this, static_cast<decltype(regex_options.value())>(parser_result.options.value()));
}

template<class Parser>
Regex<Parser>::Regex(regex::Parser::Result parse_result, ByteString pattern, typename ParserTraits<Parser>::OptionsType regex_options)
    : pattern_value(move(pattern))
    , parser_result(move(parse_result))
{
    parser_result.bytecode.template get<ByteCode>().flatten();
    run_optimization_passes();
    if (parser_result.error == regex::Error::NoError)
        matcher = make<Matcher<Parser>>(this, regex_options | static_cast<decltype(regex_options.value())>(parser_result.options.value()));
}

template<class Parser>
Regex<Parser>::Regex(Regex const& other)
    : pattern_value(other.pattern_value)
    , parser_result(other.parser_result)
{
    if (other.matcher)
        matcher = make<Matcher<Parser>>(this, other.matcher->options());
}

template<class Parser>
Regex<Parser>::Regex(Regex&& regex)
    : pattern_value(move(regex.pattern_value))
    , parser_result(move(regex.parser_result))
    , matcher(move(regex.matcher))
    , start_offset(regex.start_offset)
{
    if (matcher)
        matcher->reset_pattern({}, this);
}

template<class Parser>
Regex<Parser>& Regex<Parser>::operator=(Regex&& regex)
{
    pattern_value = move(regex.pattern_value);
    parser_result = move(regex.parser_result);
    matcher = move(regex.matcher);
    if (matcher)
        matcher->reset_pattern({}, this);
    start_offset = regex.start_offset;
    return *this;
}

template<class Parser>
typename ParserTraits<Parser>::OptionsType Regex<Parser>::options() const
{
    if (!matcher || parser_result.error != Error::NoError)
        return {};

    return matcher->options();
}

template<class Parser>
ByteString Regex<Parser>::error_string(Optional<ByteString> message) const
{
    StringBuilder eb;
    eb.append("Error during parsing of regular expression:\n"sv);
    eb.appendff("    {}\n    ", pattern_value);
    for (size_t i = 0; i < parser_result.error_token.position(); ++i)
        eb.append(' ');

    eb.appendff("^---- {}", message.value_or(get_error_string(parser_result.error)));
    return eb.to_byte_string();
}

template<typename Parser>
RegexResult Matcher<Parser>::match(RegexStringView view, Optional<typename ParserTraits<Parser>::OptionsType> regex_options) const
{
    AllOptions options = m_regex_options | regex_options.value_or({}).value();

    if constexpr (!IsSame<Parser, ECMA262>) {
        if (options.has_flag_set(AllFlags::Multiline))
            return match(view.lines(), regex_options); // FIXME: how do we know, which line ending a line has (1char or 2char)? This is needed to get the correct match offsets from start of string...
    }

    Vector<RegexStringView> views;
    views.append(view);
    return match(views, regex_options);
}

template<typename Parser>
RegexResult Matcher<Parser>::match(Vector<RegexStringView> const& views, Optional<typename ParserTraits<Parser>::OptionsType> regex_options) const
{
    // If the pattern *itself* isn't stateful, reset any changes to start_offset.
    if (!((AllFlags)m_regex_options.value() & AllFlags::Internal_Stateful))
        m_pattern->start_offset = 0;

    size_t match_count { 0 };

    MatchInput input;
    size_t operations = 0;

    input.pattern = m_pattern->pattern_value;

    input.regex_options = m_regex_options | regex_options.value_or({}).value();
    input.start_offset = m_pattern->start_offset;
    MatchState state(m_pattern->parser_result.capture_groups_count, input.regex_options);
    size_t lines_to_skip = 0;

    bool unicode = input.regex_options.has_flag_set(AllFlags::Unicode) || input.regex_options.has_flag_set(AllFlags::UnicodeSets);
    for (auto const& view : views)
        const_cast<RegexStringView&>(view).set_unicode(unicode);

    if constexpr (REGEX_DEBUG) {
        if (input.regex_options.has_flag_set(AllFlags::Internal_Stateful)) {
            if (views.size() > 1 && input.start_offset > views.first().length()) {
                dbgln("Started with start={}, goff={}, skip={}", input.start_offset, input.global_offset, lines_to_skip);
                for (auto const& view : views) {
                    if (input.start_offset < view.length() + 1)
                        break;
                    ++lines_to_skip;
                    input.start_offset -= view.length() + 1;
                    input.global_offset += view.length() + 1;
                }
                dbgln("Ended with start={}, goff={}, skip={}", input.start_offset, input.global_offset, lines_to_skip);
            }
        }
    }

    auto append_match = [](auto& input, auto& state, auto& start_position) {
        if (state.matches.size() == input.match_index)
            state.matches.empend();

        VERIFY(start_position + state.string_position - start_position <= input.view.length());
        state.matches.mutable_at(input.match_index) = { input.view.substring_view(start_position, state.string_position - start_position), input.line, start_position, input.global_offset + start_position };
    };

#if REGEX_DEBUG
    s_regex_dbg.print_header();
#endif

    bool continue_search = input.regex_options.has_flag_set(AllFlags::Global) || input.regex_options.has_flag_set(AllFlags::Multiline);
    if (input.regex_options.has_flag_set(AllFlags::Sticky))
        continue_search = false;

    auto single_match_only = input.regex_options.has_flag_set(AllFlags::SingleMatch);
    auto only_start_of_line = m_pattern->parser_result.optimization_data.only_start_of_line && !input.regex_options.has_flag_set(AllFlags::Multiline);

    auto compare_range = [insensitive = input.regex_options & AllFlags::Insensitive](auto needle, CharRange range) {
        auto upper_case_needle = needle;
        auto lower_case_needle = needle;
        if (insensitive) {
            upper_case_needle = to_ascii_uppercase(needle);
            lower_case_needle = to_ascii_lowercase(needle);
        }

        if (lower_case_needle >= range.from && lower_case_needle <= range.to)
            return 0;
        if (upper_case_needle >= range.from && upper_case_needle <= range.to)
            return 0;
        if (lower_case_needle > range.to || upper_case_needle > range.to)
            return 1;
        return -1;
    };

    for (auto const& view : views) {
        input.in_the_middle_of_a_line = false;
        if (lines_to_skip != 0) {
            ++input.line;
            --lines_to_skip;
            continue;
        }
        input.view = view;
        dbgln_if(REGEX_DEBUG, "[match] Starting match with view ({}): _{}_", view.length(), view);

        auto view_length = view.length();
        size_t view_index = m_pattern->start_offset;
        state.string_position = view_index;
        if (view.unicode()) {
            if (view_index < view_length)
                state.string_position_in_code_units = view.code_unit_offset_of(view_index);
            else
                state.string_position_in_code_units = view.length_in_code_units();
        } else {
            state.string_position_in_code_units = view_index;
        }
        bool succeeded = false;

        if (view_index == view_length && m_pattern->parser_result.match_length_minimum == 0) {
            // Run the code until it tries to consume something.
            // This allows non-consuming code to run on empty strings, for instance
            // e.g. "Exit"
            size_t temp_operations = operations;

            input.column = match_count;
            input.match_index = match_count;

            state.instruction_position = 0;
            state.repetition_marks.clear();
            state.modifier_stack.clear();
            state.current_options = input.regex_options;

            auto result = execute(input, state, temp_operations);
            // This success is acceptable only if it doesn't read anything from the input (input length is 0).
            if (result == ExecuteResult::Matched && (state.string_position <= view_index)) {
                operations = temp_operations;
                if (!match_count) {
                    // Nothing was *actually* matched, so append an empty match.
                    append_match(input, state, view_index);
                    ++match_count;

                    // This prevents a regex pattern like ".*" from matching the empty string
                    // multiple times, once in this block and once in the following for loop.
                    if (view_index == 0 && view_length == 0)
                        ++view_index;
                }
            }
        }

        for (; view_index <= view_length; ++view_index, input.in_the_middle_of_a_line = true) {
            if (view_index == view_length) {
                if (input.regex_options.has_flag_set(AllFlags::Multiline))
                    break;
            }

            // FIXME: More performant would be to know the remaining minimum string
            //        length needed to match from the current position onwards within
            //        the vm. Add new OpCode for MinMatchLengthFromSp with the value of
            //        the remaining string length from the current path. The value though
            //        has to be filled in reverse. That implies a second run over bytecode
            //        after generation has finished.
            auto const match_length_minimum = m_pattern->parser_result.match_length_minimum;
            if (match_length_minimum && match_length_minimum > view_length - view_index)
                break;

            auto const insensitive = input.regex_options.has_flag_set(AllFlags::Insensitive);
            if (auto& starting_ranges = m_pattern->parser_result.optimization_data.starting_ranges; !starting_ranges.is_empty()) {
                auto ranges = insensitive ? m_pattern->parser_result.optimization_data.starting_ranges_insensitive.span() : starting_ranges.span();
                auto code_unit_index = input.view.unicode() ? input.view.code_unit_offset_of(view_index) : view_index;
                auto ch = input.view.unicode_aware_code_point_at(code_unit_index);
                if (insensitive)
                    ch = to_ascii_lowercase(ch);

                if (!binary_search(ranges, ch, nullptr, compare_range))
                    goto done_matching;
            }

            input.column = match_count;
            input.match_index = match_count;

            state.string_position = view_index;
            if (input.view.unicode()) {
                if (view_index < view_length)
                    state.string_position_in_code_units = input.view.code_unit_offset_of(view_index);
                else
                    state.string_position_in_code_units = input.view.length_in_code_units();
            } else {
                state.string_position_in_code_units = view_index;
            }
            state.instruction_position = 0;
            state.repetition_marks.clear();
            state.modifier_stack.clear();
            state.current_options = input.regex_options;
            state.string_position_before_rseek = NumericLimits<size_t>::max();
            state.string_position_in_code_units_before_rseek = NumericLimits<size_t>::max();

            if (auto const result = execute(input, state, operations); result == ExecuteResult::Matched) {
                succeeded = true;

                if (input.regex_options.has_flag_set(AllFlags::MatchNotEndOfLine) && state.string_position == input.view.length()) {
                    if (!continue_search)
                        break;
                    continue;
                }
                if (input.regex_options.has_flag_set(AllFlags::MatchNotBeginOfLine) && view_index == 0) {
                    if (!continue_search)
                        break;
                    continue;
                }

                dbgln_if(REGEX_DEBUG, "state.string_position={}, view_index={}", state.string_position, view_index);
                dbgln_if(REGEX_DEBUG, "[match] Found a match (length={}): '{}'", state.string_position - view_index, input.view.substring_view(view_index, state.string_position - view_index));

                ++match_count;

                if (continue_search) {
                    append_match(input, state, view_index);

                    bool has_zero_length = state.string_position == view_index;
                    view_index = state.string_position - (has_zero_length ? 0 : 1);
                    if (single_match_only)
                        break;
                    continue;
                }
                if (input.regex_options.has_flag_set(AllFlags::Internal_Stateful)) {
                    append_match(input, state, view_index);
                    break;
                }
                if (state.string_position < view_length) {
                    return { false, 0, {}, {}, {}, operations };
                }

                append_match(input, state, view_index);
                break;
            } else if (result == ExecuteResult::DidNotMatchAndNoFurtherPossibleMatchesInView) {
                break;
            }

        done_matching:
            if (!continue_search || only_start_of_line)
                break;
        }

        ++input.line;
        input.global_offset += view.length() + 1; // +1 includes the line break character

        if (input.regex_options.has_flag_set(AllFlags::Internal_Stateful))
            m_pattern->start_offset = state.string_position;

        if (succeeded && !continue_search)
            break;
    }

    auto flat_capture_group_matches = move(state.flat_capture_group_matches).release();
    if (flat_capture_group_matches.size() < state.capture_group_count * match_count) {
        flat_capture_group_matches.ensure_capacity(match_count * state.capture_group_count);
        for (size_t i = flat_capture_group_matches.size(); i < match_count * state.capture_group_count; ++i)
            flat_capture_group_matches.unchecked_empend();
    }

    Vector<Span<Match>> capture_group_matches;
    for (size_t i = 0; i < match_count; ++i) {
        auto span = flat_capture_group_matches.span().slice(state.capture_group_count * i, state.capture_group_count);
        capture_group_matches.append(span);
    }

    RegexResult result {
        match_count != 0,
        match_count,
        move(state.matches).release(),
        move(flat_capture_group_matches),
        move(capture_group_matches),
        operations,
        m_pattern->parser_result.capture_groups_count,
        m_pattern->parser_result.named_capture_groups_count,
    };

    if (match_count > 0)
        VERIFY(result.capture_group_matches.size() >= match_count);
    else
        result.capture_group_matches.clear_with_capacity();

    return result;
}

template<typename T>
class BumpAllocatedLinkedList {
public:
    BumpAllocatedLinkedList() = default;

    ALWAYS_INLINE void append(T value)
    {
        auto node_ptr = m_allocator.allocate(move(value));
        VERIFY(node_ptr);

        if (!m_first) {
            m_first = node_ptr;
            m_last = node_ptr;
            return;
        }

        node_ptr->previous = m_last;
        m_last->next = node_ptr;
        m_last = node_ptr;
    }

    ALWAYS_INLINE T take_last()
    {
        VERIFY(m_last);
        T value = move(m_last->value);
        if (m_last == m_first) {
            m_last = nullptr;
            m_first = nullptr;
        } else {
            m_last = m_last->previous;
            m_last->next = nullptr;
        }
        return value;
    }

    ALWAYS_INLINE T& last()
    {
        return m_last->value;
    }

    ALWAYS_INLINE bool is_empty() const
    {
        return m_first == nullptr;
    }

    auto reverse_begin() { return ReverseIterator(m_last); }
    auto reverse_end() { return ReverseIterator(); }

private:
    struct Node {
        T value;
        Node* next { nullptr };
        Node* previous { nullptr };
    };

    struct ReverseIterator {
        ReverseIterator() = default;
        explicit ReverseIterator(Node* node)
            : m_node(node)
        {
        }

        T* operator->() { return &m_node->value; }
        T& operator*() { return m_node->value; }
        bool operator==(ReverseIterator const& it) const { return m_node == it.m_node; }
        ReverseIterator& operator++()
        {
            if (m_node)
                m_node = m_node->previous;
            return *this;
        }

    private:
        Node* m_node;
    };

    UniformBumpAllocator<Node, true, 2 * MiB> m_allocator;
    Node* m_first { nullptr };
    Node* m_last { nullptr };
};

ALWAYS_INLINE static size_t get_opcode_size(OpCodeId opcode_id, ByteCodeValueType const* data, size_t ip)
{
    switch (opcode_id) {
    case OpCodeId::Exit:
    case OpCodeId::FailForks:
    case OpCodeId::PopSaved:
    case OpCodeId::Save:
    case OpCodeId::Restore:
    case OpCodeId::IncStepBack:
    case OpCodeId::CheckStepBack:
    case OpCodeId::CheckSavedPosition:
    case OpCodeId::CheckBegin:
    case OpCodeId::CheckEnd:
    case OpCodeId::RestoreModifiers:
        return 1;
    case OpCodeId::Jump:
    case OpCodeId::ForkJump:
    case OpCodeId::ForkStay:
    case OpCodeId::ForkReplaceJump:
    case OpCodeId::ForkReplaceStay:
    case OpCodeId::GoBack:
    case OpCodeId::SetStepBack:
    case OpCodeId::SaveLeftCaptureGroup:
    case OpCodeId::SaveRightCaptureGroup:
    case OpCodeId::RSeekTo:
    case OpCodeId::CheckBoundary:
    case OpCodeId::ClearCaptureGroup:
    case OpCodeId::FailIfEmpty:
    case OpCodeId::ResetRepeat:
    case OpCodeId::Checkpoint:
    case OpCodeId::SaveModifiers:
        return 2;
    case OpCodeId::SaveRightNamedCaptureGroup:
        return 3;
    case OpCodeId::JumpNonEmpty:
    case OpCodeId::ForkIf:
    case OpCodeId::Repeat:
        return 4;
    case OpCodeId::Compare:
        return 3 + data[ip + 2];
    case OpCodeId::CompareSimple:
        return 2 + data[ip + 1];
    }
    VERIFY_NOT_REACHED();
}

ALWAYS_INLINE static ExecutionResult execute_opcode(FlatByteCode const& bytecode, OpCodeId opcode_id, ByteCodeValueType const* data, size_t ip, MatchInput const& input, MatchState& state)
{
    switch (opcode_id) {
    case OpCodeId::Exit:
        if (state.string_position > input.view.length() || state.instruction_position >= bytecode.size())
            return ExecutionResult::Succeeded;
        return ExecutionResult::Failed;

    case OpCodeId::Save:
        save_string_position(input, state);
        state.forks_since_last_save = 0;
        return ExecutionResult::Continue;

    case OpCodeId::Restore:
        if (!restore_string_position(input, state))
            return ExecutionResult::Failed;
        return ExecutionResult::Continue;

    case OpCodeId::GoBack: {
        auto count = data[ip + 1];
        if (count > state.string_position)
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        reverse_string_position(state, input.view, count);
        return ExecutionResult::Continue;
    }

    case OpCodeId::SetStepBack:
        state.step_backs.append(static_cast<i64>(data[ip + 1]));
        return ExecutionResult::Continue;

    case OpCodeId::IncStepBack: {
        if (state.step_backs.is_empty())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        size_t last_step_back = static_cast<size_t>(++state.step_backs.mutable_last());
        if (last_step_back > state.string_position)
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        reverse_string_position(state, input.view, last_step_back);
        return ExecutionResult::Continue;
    }

    case OpCodeId::CheckStepBack:
        if (state.step_backs.is_empty())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        if (input.saved_positions.is_empty())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        if (static_cast<size_t>(state.step_backs.last()) > input.saved_positions.last())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        state.string_position = input.saved_positions.last();
        state.string_position_in_code_units = input.saved_code_unit_positions.last();
        return ExecutionResult::Continue;

    case OpCodeId::CheckSavedPosition:
        if (input.saved_positions.is_empty())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        if (state.string_position != input.saved_positions.last())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        state.step_backs.take_last();
        return ExecutionResult::Continue;

    case OpCodeId::FailForks:
        input.fail_counter += state.forks_since_last_save;
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    case OpCodeId::PopSaved:
        if (input.saved_positions.is_empty() || input.saved_code_unit_positions.is_empty())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        input.saved_positions.take_last();
        input.saved_code_unit_positions.take_last();
        return ExecutionResult::Failed_ExecuteLowPrioForks;

    case OpCodeId::Jump:
        state.instruction_position += static_cast<ssize_t>(data[ip + 1]);
        return ExecutionResult::Continue;

    case OpCodeId::ForkJump: {
        auto offset = static_cast<ssize_t>(data[ip + 1]);
        state.fork_at_position = state.instruction_position + 2 + offset;
        state.forks_since_last_save++;
        return ExecutionResult::Fork_PrioHigh;
    }

    case OpCodeId::ForkStay: {
        auto offset = static_cast<ssize_t>(data[ip + 1]);
        state.fork_at_position = state.instruction_position + 2 + offset;
        state.forks_since_last_save++;
        return ExecutionResult::Fork_PrioLow;
    }

    case OpCodeId::ForkReplaceJump: {
        auto offset = static_cast<ssize_t>(data[ip + 1]);
        state.fork_at_position = state.instruction_position + 2 + offset;
        input.fork_to_replace = state.instruction_position;
        state.forks_since_last_save++;
        return ExecutionResult::Fork_PrioHigh;
    }

    case OpCodeId::ForkReplaceStay: {
        auto offset = static_cast<ssize_t>(data[ip + 1]);
        state.fork_at_position = state.instruction_position + 2 + offset;
        input.fork_to_replace = state.instruction_position;
        return ExecutionResult::Fork_PrioLow;
    }

    case OpCodeId::ForkIf: {
        auto offset = static_cast<ssize_t>(data[ip + 1]);
        auto form = static_cast<OpCodeId>(data[ip + 2]);
        auto condition = static_cast<ForkIfCondition>(data[ip + 3]);
        constexpr size_t forkif_size = 4;

        bool do_fork = false;
        switch (condition) {
        case ForkIfCondition::AtStartOfLine:
            do_fork = !input.in_the_middle_of_a_line;
            break;
        default:
            VERIFY_NOT_REACHED();
        }

        switch (form) {
        case OpCodeId::ForkJump:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + forkif_size + offset;
                state.forks_since_last_save++;
                return ExecutionResult::Fork_PrioHigh;
            }
            return ExecutionResult::Continue;
        case OpCodeId::ForkReplaceJump:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + forkif_size + offset;
                input.fork_to_replace = state.instruction_position;
                state.forks_since_last_save++;
                return ExecutionResult::Fork_PrioHigh;
            }
            return ExecutionResult::Continue;
        case OpCodeId::ForkStay:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + forkif_size + offset;
                state.forks_since_last_save++;
                return ExecutionResult::Fork_PrioLow;
            }
            state.instruction_position += offset;
            return ExecutionResult::Continue;
        case OpCodeId::ForkReplaceStay:
            if (do_fork) {
                state.fork_at_position = state.instruction_position + forkif_size + offset;
                input.fork_to_replace = state.instruction_position;
                return ExecutionResult::Fork_PrioLow;
            }
            state.instruction_position += offset;
            return ExecutionResult::Continue;
        default:
            VERIFY_NOT_REACHED();
        }
    }

    case OpCodeId::CheckBegin: {
        auto is_at_line_boundary = [&] {
            if (state.string_position == 0)
                return true;
            if (state.current_options.has_flag_set(AllFlags::Multiline) && state.current_options.has_flag_set(AllFlags::Internal_ConsiderNewline)) {
                auto ch = input.view.substring_view(state.string_position - 1, 1).code_point_at(0);
                return ch == '\r' || ch == '\n' || ch == LineSeparator || ch == ParagraphSeparator;
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

    case OpCodeId::CheckEnd: {
        auto is_at_line_boundary = [&] {
            if (state.string_position == input.view.length())
                return true;
            if (state.current_options.has_flag_set(AllFlags::Multiline) && state.current_options.has_flag_set(AllFlags::Internal_ConsiderNewline)) {
                auto ch = input.view.substring_view(state.string_position, 1).code_point_at(0);
                return ch == '\r' || ch == '\n' || ch == LineSeparator || ch == ParagraphSeparator;
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

    case OpCodeId::CheckBoundary: {
        auto type = static_cast<BoundaryCheckType>(data[ip + 1]);
        auto isword = [&](auto ch) {
            return is_word_character(ch, state.current_options & AllFlags::Insensitive, input.view.unicode());
        };
        auto at_word_boundary = [&] {
            if (state.string_position == input.view.length())
                return (state.string_position > 0 && isword(input.view.code_point_at(state.string_position_in_code_units - 1)));
            if (state.string_position == 0)
                return isword(input.view.code_point_at(0));
            return !!(isword(input.view.code_point_at(state.string_position_in_code_units)) ^ isword(input.view.code_point_at(state.string_position_in_code_units - 1)));
        };
        switch (type) {
        case BoundaryCheckType::Word:
            return at_word_boundary() ? ExecutionResult::Continue : ExecutionResult::Failed_ExecuteLowPrioForks;
        case BoundaryCheckType::NonWord:
            return !at_word_boundary() ? ExecutionResult::Continue : ExecutionResult::Failed_ExecuteLowPrioForks;
        }
        VERIFY_NOT_REACHED();
    }

    case OpCodeId::ClearCaptureGroup: {
        auto id = data[ip + 1];
        if (input.match_index < state.capture_group_matches_size()) {
            auto group = state.mutable_capture_group_matches(input.match_index);
            group[id - 1].reset();
        }
        return ExecutionResult::Continue;
    }

    case OpCodeId::SaveLeftCaptureGroup: {
        auto id = data[ip + 1];
        if (input.match_index >= state.capture_group_matches_size()) {
            state.flat_capture_group_matches.ensure_capacity((input.match_index + 1) * state.capture_group_count);
            for (size_t i = state.capture_group_matches_size(); i <= input.match_index; ++i)
                for (size_t j = 0; j < state.capture_group_count; ++j)
                    state.flat_capture_group_matches.append({});
        }
        state.mutable_capture_group_matches(input.match_index).at(id - 1).left_column = state.string_position;
        return ExecutionResult::Continue;
    }

    case OpCodeId::SaveRightCaptureGroup: {
        auto id = data[ip + 1];
        auto& match = state.capture_group_matches(input.match_index).at(id - 1);
        auto start_position = match.left_column;
        if (state.string_position < start_position) {
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        }
        auto length = state.string_position - start_position;
        if (start_position < match.column && state.step_backs.is_empty())
            return ExecutionResult::Continue;
        VERIFY(start_position + length <= input.view.length_in_code_units());
        auto captured_text = input.view.substring_view(start_position, length);
        auto& existing_capture = state.mutable_capture_group_matches(input.match_index).at(id - 1);
        if (length == 0 && !existing_capture.view.is_null() && existing_capture.view.length() > 0) {
            auto existing_end_position = existing_capture.global_offset - input.global_offset + existing_capture.view.length();
            if (existing_end_position == state.string_position)
                return ExecutionResult::Continue;
        }
        state.mutable_capture_group_matches(input.match_index).at(id - 1) = { captured_text, input.line, start_position, input.global_offset + start_position };
        return ExecutionResult::Continue;
    }

    case OpCodeId::SaveRightNamedCaptureGroup: {
        auto name_string_table_index = data[ip + 1];
        auto id = data[ip + 2];
        auto& match = state.capture_group_matches(input.match_index).at(id - 1);
        auto start_position = match.left_column;
        if (state.string_position < start_position)
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        auto length = state.string_position - start_position;
        if (start_position < match.column)
            return ExecutionResult::Continue;
        VERIFY(start_position + length <= input.view.length_in_code_units());
        auto view = input.view.substring_view(start_position, length);
        auto& existing_capture = state.mutable_capture_group_matches(input.match_index).at(id - 1);
        if (length == 0 && !existing_capture.view.is_null() && existing_capture.view.length() > 0) {
            auto existing_end_position = existing_capture.global_offset - input.global_offset + existing_capture.view.length();
            if (existing_end_position == state.string_position)
                return ExecutionResult::Continue;
        }
        state.mutable_capture_group_matches(input.match_index).at(id - 1) = { view, name_string_table_index, input.line, start_position, input.global_offset + start_position };
        return ExecutionResult::Continue;
    }

    case OpCodeId::RSeekTo: {
        auto ch = data[ip + 1];
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

    case OpCodeId::FailIfEmpty: {
        auto checkpoint_id = data[ip + 1];
        u64 current_position = state.string_position + 1;
        auto checkpoint_position = state.checkpoints.get(checkpoint_id).value_or(current_position);
        if (checkpoint_position == current_position)
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        return ExecutionResult::Continue;
    }

    case OpCodeId::Repeat: {
        auto offset = data[ip + 1];
        auto count = data[ip + 2];
        auto id = data[ip + 3];
        VERIFY(count > 0);
        if (id >= state.repetition_marks.size())
            state.repetition_marks.resize(id + 1);
        auto& repetition_mark = state.repetition_marks.mutable_at(id);
        if (repetition_mark == count - 1) {
            repetition_mark = 0;
        } else {
            state.instruction_position -= offset + 4;
            ++repetition_mark;
        }
        return ExecutionResult::Continue;
    }

    case OpCodeId::ResetRepeat: {
        auto id = data[ip + 1];
        if (id >= state.repetition_marks.size())
            state.repetition_marks.resize(id + 1);
        state.repetition_marks.mutable_at(id) = 0;
        return ExecutionResult::Continue;
    }

    case OpCodeId::Checkpoint: {
        auto id = data[ip + 1];
        if (id >= state.checkpoints.size())
            state.checkpoints.resize(id + 1);
        state.checkpoints.mutable_at(id) = state.string_position + 1;
        return ExecutionResult::Continue;
    }

    case OpCodeId::JumpNonEmpty: {
        auto offset = static_cast<ssize_t>(data[ip + 1]);
        auto checkpoint_id = data[ip + 2];
        auto form = static_cast<OpCodeId>(data[ip + 3]);
        constexpr size_t jne_size = 4;

        u64 current_position = state.string_position;
        auto checkpoint_position = state.checkpoints.get(checkpoint_id).value_or(0);

        if (checkpoint_position != 0 && checkpoint_position != current_position + 1) {
            if (form == OpCodeId::Jump) {
                state.instruction_position += offset;
                return ExecutionResult::Continue;
            }
            state.fork_at_position = state.instruction_position + jne_size + offset;
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
        if (form == OpCodeId::Jump && state.string_position < input.view.length())
            return ExecutionResult::Failed_ExecuteLowPrioForks;
        return ExecutionResult::Continue;
    }

    case OpCodeId::SaveModifiers: {
        auto new_modifiers = data[ip + 1];
        auto current_flags = to_underlying(state.current_options.value());
        state.modifier_stack.append(current_flags);
        state.current_options = AllOptions { static_cast<AllFlags>(new_modifiers) };
        return ExecutionResult::Continue;
    }

    case OpCodeId::RestoreModifiers: {
        if (state.modifier_stack.is_empty())
            return ExecutionResult::Failed;
        auto previous_modifiers = state.modifier_stack.take_last();
        state.current_options = AllOptions { static_cast<AllFlags>(previous_modifiers) };
        return ExecutionResult::Continue;
    }

    case OpCodeId::Compare:
        return CompareInternals<FlatByteCode, false>::execute_impl(bytecode, data, ip, input, state);

    case OpCodeId::CompareSimple:
        return CompareInternals<FlatByteCode, true>::execute_impl(bytecode, data, ip, input, state);
    }

    VERIFY_NOT_REACHED();
}

template<class Parser>
Matcher<Parser>::ExecuteResult Matcher<Parser>::execute(MatchInput const& input, MatchState& state, size_t& operations) const
{
    if (m_pattern->parser_result.optimization_data.pure_substring_search.has_value() && input.view.is_u16_view()) {
        // Yay, we can do a simple substring search!
        auto is_insensitive = input.regex_options.has_flag_set(AllFlags::Insensitive);
        auto is_unicode = input.view.unicode() || input.regex_options.has_flag_set(AllFlags::Unicode) || input.regex_options.has_flag_set(AllFlags::UnicodeSets);
        // Utf16View::equals_ignoring_case can't handle unicode case folding, so we can only use it for ASCII case insensitivity.
        if (!(is_insensitive && is_unicode)) {
            auto input_view = input.view.u16_view();
            Span<u16 const> needle = m_pattern->parser_result.optimization_data.pure_substring_search->span();
            Utf16View needle_view { bit_cast<char16_t const*>(needle.data()), needle.size() };

            if (is_unicode) {
                if (needle_view.length_in_code_points() + state.string_position > input_view.length_in_code_points())
                    return ExecuteResult::DidNotMatch;
            } else {
                if (needle_view.length_in_code_units() + state.string_position_in_code_units > input_view.length_in_code_units())
                    return ExecuteResult::DidNotMatch;
            }

            Utf16View haystack;
            if (is_unicode)
                haystack = input_view.unicode_substring_view(state.string_position, needle_view.length_in_code_points());
            else
                haystack = input_view.substring_view(state.string_position_in_code_units, needle_view.length_in_code_units());

            if (is_insensitive) {
                if (!Unicode::ranges_equal_ignoring_case(haystack, needle_view, input.view.unicode()))
                    return ExecuteResult::DidNotMatch;
            } else {
                if (haystack != needle_view)
                    return ExecuteResult::DidNotMatch;
            }

            if (input.view.unicode())
                state.string_position += haystack.length_in_code_points();
            else
                state.string_position += haystack.length_in_code_units();
            state.string_position_in_code_units += haystack.length_in_code_units();
            return ExecuteResult::Matched;
        }
    }

    if (auto const& nfa = m_pattern->parser_result.optimization_data.nfa_graph; nfa.has_value()) {
        auto& bytecode = m_pattern->parser_result.bytecode.template get<FlatByteCode>();
        auto result = execute_nfa(*nfa, bytecode, input, state);
        if (result == NFAExecuteResult::Matched)
            return ExecuteResult::Matched;
        return ExecuteResult::DidNotMatch;
    }

    BumpAllocatedLinkedList<MatchState> states_to_try_next;
    HashTable<u64, IdentityHashTraits<u64>> seen_state_hashes;
#if REGEX_DEBUG
    size_t recursion_level = 0;
#endif

    auto& bytecode = m_pattern->parser_result.bytecode.template get<FlatByteCode>();
    auto const* data = bytecode.flat_data().data();
    auto bytecode_size = bytecode.size();

    for (;;) {
        auto ip = state.instruction_position;
        OpCodeId opcode_id = (ip < bytecode_size)
            ? static_cast<OpCodeId>(data[ip])
            : OpCodeId::Exit;

        auto const opcode_size = get_opcode_size(opcode_id, data, ip);
        ++operations;

#if REGEX_DEBUG
        auto& opcode = bytecode.get_opcode(state);
        s_regex_dbg.print_opcode("VM", opcode, state, recursion_level, false);
#endif

        ExecutionResult result;
        if (input.fail_counter > 0) {
            --input.fail_counter;
            result = ExecutionResult::Failed_ExecuteLowPrioForks;
        } else {
            result = execute_opcode(bytecode, opcode_id, data, ip, input, state);
        }

#if REGEX_DEBUG
        s_regex_dbg.print_result(opcode, bytecode, input, state, result);
#endif

        state.instruction_position += opcode_size;

        switch (result) {
        case ExecutionResult::Fork_PrioLow: {
            bool found = false;
            if (input.fork_to_replace.has_value()) {
                for (auto it = states_to_try_next.reverse_begin(); it != states_to_try_next.reverse_end(); ++it) {
                    if (it->initiating_fork == input.fork_to_replace.value()) {
                        (*it) = state;
                        it->instruction_position = state.fork_at_position;
                        it->initiating_fork = *input.fork_to_replace;
                        found = true;
                        break;
                    }
                }
                input.fork_to_replace.clear();
            }
            if (!found) {
                states_to_try_next.append(state);
                states_to_try_next.last().initiating_fork = state.instruction_position - opcode_size;
                states_to_try_next.last().instruction_position = state.fork_at_position;
            }
            state.string_position_before_rseek = NumericLimits<size_t>::max();
            state.string_position_in_code_units_before_rseek = NumericLimits<size_t>::max();
            continue;
        }
        case ExecutionResult::Fork_PrioHigh: {
            bool found = false;
            if (input.fork_to_replace.has_value()) {
                for (auto it = states_to_try_next.reverse_begin(); it != states_to_try_next.reverse_end(); ++it) {
                    if (it->initiating_fork == input.fork_to_replace.value()) {
                        (*it) = state;
                        it->initiating_fork = *input.fork_to_replace;
                        found = true;
                        break;
                    }
                }
                input.fork_to_replace.clear();
            }
            if (!found) {
                states_to_try_next.append(state);
                states_to_try_next.last().initiating_fork = state.instruction_position - opcode_size;
                states_to_try_next.last().string_position_before_rseek = NumericLimits<size_t>::max();
                states_to_try_next.last().string_position_in_code_units_before_rseek = NumericLimits<size_t>::max();
            }
            state.instruction_position = state.fork_at_position;
#if REGEX_DEBUG
            ++recursion_level;
#endif
            continue;
        }
        case ExecutionResult::Continue:
            continue;
        case ExecutionResult::Succeeded:
            return ExecuteResult::Matched;
        case ExecutionResult::Failed: {
            bool found = false;
            while (!states_to_try_next.is_empty()) {
                state = states_to_try_next.take_last();
                if (auto hash = state.u64_hash(); seen_state_hashes.set(hash) != HashSetResult::InsertedNewEntry) {
                    dbgln_if(REGEX_DEBUG, "Already seen state, skipping: {}", hash);
                    continue;
                }
                found = true;
                break;
            }
            if (found)
                continue;
            return ExecuteResult::DidNotMatch;
        }
        case ExecutionResult::Failed_ExecuteLowPrioForks: {
            bool found = false;
            while (!states_to_try_next.is_empty()) {
                state = states_to_try_next.take_last();
                if (auto hash = state.u64_hash(); seen_state_hashes.set(hash) != HashSetResult::InsertedNewEntry) {
                    dbgln_if(REGEX_DEBUG, "Already seen state, skipping: {}", hash);
                    continue;
                }
                found = true;
                break;
            }
            if (!found)
                return ExecuteResult::DidNotMatch;
#if REGEX_DEBUG
            ++recursion_level;
#endif
            continue;
        }
        case ExecutionResult::Failed_ExecuteLowPrioForksButNoFurtherPossibleMatches: {
            bool found = false;
            while (!states_to_try_next.is_empty()) {
                state = states_to_try_next.take_last();
                if (auto hash = state.u64_hash(); seen_state_hashes.set(hash) != HashSetResult::InsertedNewEntry) {
                    dbgln_if(REGEX_DEBUG, "Already seen state, skipping: {}", hash);
                    continue;
                }
                found = true;
                break;
            }
            if (!found)
                return ExecuteResult::DidNotMatchAndNoFurtherPossibleMatchesInView;
#if REGEX_DEBUG
            ++recursion_level;
#endif
            continue;
        }
        }
    }

    VERIFY_NOT_REACHED();
}

template class Matcher<PosixBasicParser>;
template class Regex<PosixBasicParser>;

template class Matcher<PosixExtendedParser>;
template class Regex<PosixExtendedParser>;

template class Matcher<ECMA262Parser>;
template class Regex<ECMA262Parser>;

}

template<typename Parser>
struct AK::Traits<regex::CacheKey<Parser>> : public AK::DefaultTraits<regex::CacheKey<Parser>> {
    static unsigned hash(regex::CacheKey<Parser> const& key)
    {
        return pair_int_hash(key.pattern.hash(), to_underlying(key.options.value()));
    }
};
