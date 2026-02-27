/*
 * Copyright (c) 2025, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Debug.h>
#include <LibRegex/RegexNFA.h>
#include <LibUnicode/CharacterTypes.h>

namespace regex {

// build_nfa: Convert flat bytecode into an NFA graph.
// Returns nullopt if the pattern uses features unsupported by NFA simulation
// (backreferences, lookaround, etc.)
Optional<NFAGraph> build_nfa(FlatByteCode const& bytecode)
{
    auto const* data = bytecode.flat_data().data();
    auto bytecode_size = bytecode.size();

    if (bytecode_size == 0)
        return {};

    NFAGraph graph;
    // Map from bytecode IP -> NFA node index
    HashMap<size_t, u32> ip_to_node;

    // First pass: create nodes for each instruction position
    // We also create matchers for Compare/CompareSimple instructions
    size_t ip = 0;
    while (ip < bytecode_size) {
        auto opcode_id = static_cast<OpCodeId>(data[ip]);
        auto node_index = static_cast<u32>(graph.nodes.size());
        ip_to_node.set(ip, node_index);

        switch (opcode_id) {
        case OpCodeId::Compare: {
            // Check for unsupported compare types - bail out
            auto arguments_count = data[ip + 1];
            auto arguments_size = data[ip + 2];
            size_t offset = ip + 3;
            bool has_unsupported = false;
            for (size_t i = 0; i < arguments_count; ++i) {
                auto compare_type = static_cast<CharacterCompareType>(data[offset]);
                // Backreferences require backtracking
                // String/StringSet consume multiple characters which breaks Pike NFA's one-char-at-a-time invariant
                if (compare_type == CharacterCompareType::Reference
                    || compare_type == CharacterCompareType::NamedReference
                    || compare_type == CharacterCompareType::String
                    || compare_type == CharacterCompareType::StringSet) {
                    has_unsupported = true;
                    break;
                }
                // Skip past this compare argument
                switch (compare_type) {
                case CharacterCompareType::Inverse:
                case CharacterCompareType::TemporaryInverse:
                case CharacterCompareType::AnyChar:
                    offset += 1;
                    break;
                case CharacterCompareType::Char:
                case CharacterCompareType::CharClass:
                    offset += 2;
                    break;
                case CharacterCompareType::String:
                case CharacterCompareType::Reference:
                case CharacterCompareType::NamedReference:
                    offset += 2;
                    break;
                case CharacterCompareType::CharRange:
                    offset += 2; // CharRange is packed into one u64
                    break;
                case CharacterCompareType::Property:
                case CharacterCompareType::GeneralCategory:
                case CharacterCompareType::Script:
                case CharacterCompareType::ScriptExtension:
                    offset += 2;
                    break;
                case CharacterCompareType::LookupTable: {
                    auto count_sensitive = data[offset + 1];
                    auto count_insensitive = data[offset + 2];
                    offset += 3 + count_sensitive + count_insensitive;
                    break;
                }
                case CharacterCompareType::RangeExpressionDummy:
                    offset += 1;
                    break;
                case CharacterCompareType::And:
                case CharacterCompareType::Or:
                case CharacterCompareType::EndAndOr:
                case CharacterCompareType::Subtract:
                    offset += 1;
                    break;
                case CharacterCompareType::StringSet:
                    offset += 2; // string set index
                    break;
                default:
                    offset += 1;
                    break;
                }
            }
            if (has_unsupported)
                return {};

            NFANode node;
            node.type = NFANode::Type::Match;
            node.data_index = static_cast<u32>(graph.matchers.size());

            // Check if this is a simple single-char compare
            NFAMatcher matcher;
            matcher.bytecode_ip = ip;
            if (arguments_count == 1) {
                size_t arg_offset = ip + 3;
                auto ct = static_cast<CharacterCompareType>(data[arg_offset]);
                if (ct == CharacterCompareType::Char)
                    matcher.single_char = static_cast<u32>(data[arg_offset + 1]);
            }
            graph.matchers.append(matcher);
            graph.nodes.append(node);
            ip += 3 + arguments_size;
            break;
        }
        case OpCodeId::CompareSimple: {
            // Check for unsupported compare types - bail out
            auto arguments_size = data[ip + 1];
            size_t offset = ip + 2;
            auto compare_type = static_cast<CharacterCompareType>(data[offset]);
            if (compare_type == CharacterCompareType::Reference
                || compare_type == CharacterCompareType::NamedReference
                || compare_type == CharacterCompareType::String
                || compare_type == CharacterCompareType::StringSet)
                return {};

            NFANode node;
            node.type = NFANode::Type::Match;
            node.data_index = static_cast<u32>(graph.matchers.size());

            NFAMatcher matcher;
            matcher.bytecode_ip = ip;
            if (compare_type == CharacterCompareType::Char)
                matcher.single_char = static_cast<u32>(data[offset + 1]);
            graph.matchers.append(matcher);
            graph.nodes.append(node);
            ip += 2 + arguments_size;
            break;
        }
        case OpCodeId::ForkJump:
        case OpCodeId::ForkStay:
        case OpCodeId::ForkReplaceJump:
        case OpCodeId::ForkReplaceStay: {
            NFANode node;
            node.type = NFANode::Type::Split;
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::Jump: {
            // Epsilon node - will wire out1 to target in second pass
            NFANode node;
            node.type = NFANode::Type::Split; // We'll use as single-target epsilon
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::JumpNonEmpty: {
            // This is like a conditional fork. Create a Split node.
            NFANode node;
            node.type = NFANode::Type::Split;
            graph.nodes.append(node);
            ip += 4;
            break;
        }
        case OpCodeId::CheckBegin: {
            NFANode node;
            node.type = NFANode::Type::AssertBegin;
            graph.nodes.append(node);
            ip += 1;
            break;
        }
        case OpCodeId::CheckEnd: {
            NFANode node;
            node.type = NFANode::Type::AssertEnd;
            graph.nodes.append(node);
            ip += 1;
            break;
        }
        case OpCodeId::CheckBoundary: {
            NFANode node;
            node.type = NFANode::Type::AssertBoundary;
            auto boundary_type = static_cast<BoundaryCheckType>(data[ip + 1]);
            node.boundary_negated = (boundary_type == BoundaryCheckType::NonWord);
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::SaveLeftCaptureGroup: {
            NFANode node;
            node.type = NFANode::Type::CaptureOpen;
            node.data_index = static_cast<u32>(data[ip + 1]);
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::SaveRightCaptureGroup: {
            NFANode node;
            node.type = NFANode::Type::CaptureClose;
            node.data_index = static_cast<u32>(data[ip + 1]);
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::SaveRightNamedCaptureGroup: {
            NFANode node;
            node.type = NFANode::Type::CaptureClose;
            auto name_string_table_index = data[ip + 1];
            auto group_id = static_cast<u32>(data[ip + 2]);
            node.data_index = group_id;
            graph.named_capture_group_names.set(group_id, name_string_table_index);
            graph.nodes.append(node);
            ip += 3;
            break;
        }
        case OpCodeId::ClearCaptureGroup: {
            NFANode node;
            node.type = NFANode::Type::ClearCapture;
            node.data_index = static_cast<u32>(data[ip + 1]);
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::Checkpoint: {
            NFANode node;
            node.type = NFANode::Type::Checkpoint;
            node.data_index = static_cast<u32>(data[ip + 1]); // checkpoint id
            graph.checkpoint_count = max(graph.checkpoint_count, static_cast<size_t>(node.data_index + 1));
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::FailIfEmpty: {
            NFANode node;
            node.type = NFANode::Type::FailIfEmpty;
            node.data_index = static_cast<u32>(data[ip + 1]); // checkpoint id
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::ResetRepeat: {
            // Epsilon to next IP
            NFANode node;
            node.type = NFANode::Type::Split; // Single-target epsilon
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::SaveModifiers: {
            NFANode node;
            node.type = NFANode::Type::SaveModifiers;
            node.data_index = static_cast<u32>(data[ip + 1]);
            graph.nodes.append(node);
            ip += 2;
            break;
        }
        case OpCodeId::RestoreModifiers: {
            NFANode node;
            node.type = NFANode::Type::RestoreModifiers;
            graph.nodes.append(node);
            ip += 1;
            break;
        }
        case OpCodeId::Exit: {
            NFANode node;
            node.type = NFANode::Type::Accept;
            graph.nodes.append(node);
            ip += 1;
            break;
        }
        // Bail out for unsupported opcodes
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
            return {};
        }

        // Guard against state explosion
        if (graph.nodes.size() > 10000)
            return {};
    }

    // Create explicit Accept node if the bytecode doesn't end with Exit
    if (graph.nodes.is_empty() || graph.nodes.last().type != NFANode::Type::Accept) {
        auto accept_index = static_cast<u32>(graph.nodes.size());
        ip_to_node.set(bytecode_size, accept_index);
        NFANode accept_node;
        accept_node.type = NFANode::Type::Accept;
        graph.nodes.append(accept_node);
    }

    graph.accept = static_cast<u32>(graph.nodes.size() - 1);
    graph.start = 0;

    // Helper: resolve bytecode IP to NFA node, clamping to accept
    auto resolve = [&](size_t target_ip) -> u32 {
        auto it = ip_to_node.find(target_ip);
        if (it != ip_to_node.end())
            return it->value;
        // Target might be past the end → accept
        if (target_ip >= bytecode_size)
            return graph.accept;
        // Should not happen with well-formed bytecode, but be safe
        return graph.accept;
    };

    // Second pass: wire transitions
    ip = 0;
    size_t node_idx = 0;
    while (ip < bytecode_size) {
        auto opcode_id = static_cast<OpCodeId>(data[ip]);
        auto& node = graph.nodes[node_idx];
        size_t next_ip;

        switch (opcode_id) {
        case OpCodeId::Compare:
            next_ip = ip + 3 + data[ip + 2];
            node.out1 = resolve(next_ip);
            break;
        case OpCodeId::CompareSimple:
            next_ip = ip + 2 + data[ip + 1];
            node.out1 = resolve(next_ip);
            break;
        case OpCodeId::ForkStay:
        case OpCodeId::ForkReplaceStay: {
            // Greedy: out1 = next IP (try staying, high priority), out2 = jump target (low priority)
            auto offset = static_cast<ssize_t>(data[ip + 1]);
            next_ip = ip + 2;
            node.out1 = resolve(next_ip);
            node.out2 = resolve(next_ip + offset);
            break;
        }
        case OpCodeId::ForkJump:
        case OpCodeId::ForkReplaceJump: {
            // Non-greedy: out1 = jump target (high priority), out2 = next IP (low priority)
            auto offset = static_cast<ssize_t>(data[ip + 1]);
            next_ip = ip + 2;
            node.out1 = resolve(next_ip + offset);
            node.out2 = resolve(next_ip);
            break;
        }
        case OpCodeId::Jump: {
            auto offset = static_cast<ssize_t>(data[ip + 1]);
            next_ip = ip + 2;
            auto target = resolve(next_ip + offset);
            node.out1 = target;
            node.out2 = target; // Same target - effectively an epsilon
            break;
        }
        case OpCodeId::JumpNonEmpty: {
            // JumpNonEmpty <offset> <checkpoint_id> <form>
            // In NFA context, we treat this like a conditional jump.
            // The form tells us the fork semantics.
            auto offset = static_cast<ssize_t>(data[ip + 1]);
            auto form = static_cast<OpCodeId>(data[ip + 3]);
            next_ip = ip + 4;
            auto jump_target = resolve(next_ip + offset);
            auto fallthrough = resolve(next_ip);

            switch (form) {
            case OpCodeId::Jump:
                // Unconditional back-edge (for NFA purposes)
                node.out1 = jump_target;
                node.out2 = jump_target;
                break;
            case OpCodeId::ForkJump:
            case OpCodeId::ForkReplaceJump:
                // High-priority jump (non-greedy-like)
                node.out1 = jump_target;
                node.out2 = fallthrough;
                break;
            case OpCodeId::ForkStay:
            case OpCodeId::ForkReplaceStay:
                // High-priority stay (greedy-like)
                node.out1 = fallthrough;
                node.out2 = jump_target;
                break;
            default:
                node.out1 = fallthrough;
                node.out2 = fallthrough;
                break;
            }
            break;
        }
        case OpCodeId::CheckBegin:
        case OpCodeId::CheckEnd: {
            next_ip = ip + 1;
            node.out1 = resolve(next_ip);
            break;
        }
        case OpCodeId::CheckBoundary: {
            next_ip = ip + 2;
            node.out1 = resolve(next_ip);
            break;
        }
        case OpCodeId::SaveLeftCaptureGroup:
        case OpCodeId::SaveRightCaptureGroup:
        case OpCodeId::ClearCaptureGroup:
        case OpCodeId::Checkpoint:
        case OpCodeId::FailIfEmpty:
        case OpCodeId::ResetRepeat:
        case OpCodeId::SaveModifiers: {
            next_ip = ip + 2;
            node.out1 = resolve(next_ip);
            break;
        }
        case OpCodeId::SaveRightNamedCaptureGroup: {
            next_ip = ip + 3;
            node.out1 = resolve(next_ip);
            node.out2 = node.out1;
            break;
        }
        case OpCodeId::RestoreModifiers: {
            next_ip = ip + 1;
            node.out1 = resolve(next_ip);
            node.out2 = node.out1;
            break;
        }
        case OpCodeId::Exit:
            // Accept node, no outgoing edges needed
            break;
        default:
            return {};
        }

        // Advance ip to next instruction
        switch (opcode_id) {
        case OpCodeId::Compare:
            ip += 3 + data[ip + 2];
            break;
        case OpCodeId::CompareSimple:
            ip += 2 + data[ip + 1];
            break;
        case OpCodeId::Exit:
        case OpCodeId::CheckBegin:
        case OpCodeId::CheckEnd:
        case OpCodeId::RestoreModifiers:
            ip += 1;
            break;
        case OpCodeId::Jump:
        case OpCodeId::ForkJump:
        case OpCodeId::ForkStay:
        case OpCodeId::ForkReplaceJump:
        case OpCodeId::ForkReplaceStay:
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
        default:
            return {};
        }
        ++node_idx;
    }

    return graph;
}

// --- Pike NFA simulation ---

static constexpr size_t MAX_MODIFIER_DEPTH = 8;

// Working thread used during epsilon closure in add_thread().
// Captures and checkpoints are pointers into caller-owned buffers.
struct NFAThread {
    size_t* captures;       // [group*2] = start, [group*2+1] = end
    size_t* checkpoints;    // Indexed by checkpoint id
    FlagsUnderlyingType modifier_stack[MAX_MODIFIER_DEPTH];
    u8 modifier_depth { 0 };
    AllOptions current_options;
};

// Flat-array thread list for O(1) per-thread storage with minimal allocation.
struct NFAThreadList {
    Vector<size_t> flat_captures;       // [num_states * capture_slots]
    Vector<size_t> flat_checkpoints;    // [num_states * checkpoint_slots]
    Vector<AllOptions> thread_options;   // [num_states]
    Vector<FlagsUnderlyingType> flat_modifier_stacks; // [num_states * MAX_MODIFIER_DEPTH]
    Vector<u8> modifier_depths;         // [num_states]
    Vector<u32> active;
    Vector<u64> generation;
    u64 gen { 1 };
    size_t capture_slots { 0 };
    size_t checkpoint_slots { 0 };

    void init(size_t num_states, size_t caps, size_t checkpoints, AllOptions initial_options)
    {
        capture_slots = caps;
        checkpoint_slots = checkpoints;
        flat_captures.resize(num_states * caps);
        if (checkpoints > 0)
            flat_checkpoints.resize(num_states * checkpoints);
        thread_options.resize(num_states);
        for (auto& o : thread_options)
            o = initial_options;
        flat_modifier_stacks.resize(num_states * MAX_MODIFIER_DEPTH);
        modifier_depths.resize(num_states);
        generation.resize(num_states);
        for (auto& g : generation)
            g = 0;
        active.ensure_capacity(num_states);
    }

    void clear()
    {
        ++gen;
        active.clear_with_capacity();
    }

    bool has(u32 s) const { return generation[s] == gen; }

    size_t* captures_for(u32 s) { return &flat_captures[s * capture_slots]; }
    size_t const* captures_for(u32 s) const { return &flat_captures[s * capture_slots]; }

    void add(u32 s, NFAThread const& t)
    {
        if (has(s))
            return; // First thread (highest priority) wins
        generation[s] = gen;
        if (capture_slots > 0)
            memcpy(captures_for(s), t.captures, capture_slots * sizeof(size_t));
        if (checkpoint_slots > 0)
            memcpy(&flat_checkpoints[s * checkpoint_slots], t.checkpoints, checkpoint_slots * sizeof(size_t));
        thread_options[s] = t.current_options;
        memcpy(&flat_modifier_stacks[s * MAX_MODIFIER_DEPTH], t.modifier_stack, t.modifier_depth * sizeof(FlagsUnderlyingType));
        modifier_depths[s] = t.modifier_depth;
        active.append(s);
    }

    // Load thread state from flat storage into a working thread
    void load_thread(u32 s, NFAThread& t) const
    {
        if (capture_slots > 0)
            memcpy(t.captures, &flat_captures[s * capture_slots], capture_slots * sizeof(size_t));
        if (checkpoint_slots > 0)
            memcpy(t.checkpoints, &flat_checkpoints[s * checkpoint_slots], checkpoint_slots * sizeof(size_t));
        t.current_options = thread_options[s];
        t.modifier_depth = modifier_depths[s];
        memcpy(t.modifier_stack, &flat_modifier_stacks[s * MAX_MODIFIER_DEPTH], t.modifier_depth * sizeof(FlagsUnderlyingType));
    }
};

static void add_thread(
    NFAThreadList& list,
    NFAGraph const& graph,
    u32 state,
    NFAThread& thread,
    MatchInput const& input,
    MatchState const& match_state,
    size_t capture_slots)
{
    if (state >= graph.nodes.size())
        return;
    if (list.has(state))
        return;

    auto const& node = graph.nodes[state];

    // For all epsilon (non-consuming) node types, mark as visited before recursing
    // to prevent infinite loops through epsilon cycles (e.g. (a?b??)*).
    if (node.type != NFANode::Type::Match && node.type != NFANode::Type::Accept)
        list.generation[state] = list.gen;

    switch (node.type) {
    case NFANode::Type::Split: {
        add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        if (node.out1 != node.out2)
            add_thread(list, graph, node.out2, thread, input, match_state, capture_slots);
        return;
    }
    case NFANode::Type::CaptureOpen: {
        size_t group_id = node.data_index;
        size_t slot = (group_id - 1) * 2;
        if (group_id > 0 && slot < capture_slots) {
            auto saved = thread.captures[slot];
            thread.captures[slot] = match_state.string_position;
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
            thread.captures[slot] = saved;
        } else {
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        }
        return;
    }
    case NFANode::Type::CaptureClose: {
        size_t group_id = node.data_index;
        size_t slot = ((group_id - 1) * 2) + 1;
        if (group_id > 0 && slot < capture_slots) {
            auto saved = thread.captures[slot];
            thread.captures[slot] = match_state.string_position;
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
            thread.captures[slot] = saved;
        } else {
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        }
        return;
    }
    case NFANode::Type::ClearCapture: {
        size_t group_id = node.data_index;
        size_t slot_start = (group_id - 1) * 2;
        size_t slot_end = slot_start + 1;
        if (group_id > 0 && slot_end < capture_slots) {
            auto saved_start = thread.captures[slot_start];
            auto saved_end = thread.captures[slot_end];
            thread.captures[slot_start] = NumericLimits<size_t>::max();
            thread.captures[slot_end] = NumericLimits<size_t>::max();
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
            thread.captures[slot_start] = saved_start;
            thread.captures[slot_end] = saved_end;
        } else {
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        }
        return;
    }
    case NFANode::Type::AssertBegin: {
        auto is_at_line_boundary = [&] {
            if (match_state.string_position == 0)
                return true;
            if (thread.current_options.has_flag_set(AllFlags::Multiline) && thread.current_options.has_flag_set(AllFlags::Internal_ConsiderNewline)) {
                auto ch = input.view.substring_view(match_state.string_position - 1, 1).code_point_at(0);
                return ch == '\r' || ch == '\n' || ch == LineSeparator || ch == ParagraphSeparator;
            }
            return false;
        }();
        if (is_at_line_boundary && !(thread.current_options & AllFlags::MatchNotBeginOfLine))
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        else if (!is_at_line_boundary && (thread.current_options & AllFlags::MatchNotBeginOfLine))
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        else if (is_at_line_boundary && (thread.current_options & AllFlags::Global))
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        return;
    }
    case NFANode::Type::AssertEnd: {
        auto is_at_line_boundary = [&] {
            if (match_state.string_position == input.view.length())
                return true;
            if (thread.current_options.has_flag_set(AllFlags::Multiline) && thread.current_options.has_flag_set(AllFlags::Internal_ConsiderNewline)) {
                auto ch = input.view.substring_view(match_state.string_position, 1).code_point_at(0);
                return ch == '\r' || ch == '\n' || ch == LineSeparator || ch == ParagraphSeparator;
            }
            return false;
        }();
        if (is_at_line_boundary && !(thread.current_options & AllFlags::MatchNotEndOfLine))
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        else if (!is_at_line_boundary && ((thread.current_options & AllFlags::MatchNotEndOfLine) || (thread.current_options & AllFlags::MatchNotBeginOfLine)))
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        return;
    }
    case NFANode::Type::AssertBoundary: {
        auto isword = [&](auto ch) {
            return is_word_character(ch, thread.current_options & AllFlags::Insensitive, input.view.unicode());
        };
        auto at_word_boundary = [&] {
            if (match_state.string_position == input.view.length())
                return (match_state.string_position > 0 && isword(input.view.code_point_at(match_state.string_position_in_code_units - 1)));
            if (match_state.string_position == 0)
                return isword(input.view.code_point_at(0));
            return !!(isword(input.view.code_point_at(match_state.string_position_in_code_units)) ^ isword(input.view.code_point_at(match_state.string_position_in_code_units - 1)));
        };

        bool boundary = at_word_boundary();
        if (node.boundary_negated)
            boundary = !boundary;
        if (boundary)
            add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        return;
    }
    case NFANode::Type::Checkpoint: {
        auto checkpoint_id = static_cast<size_t>(node.data_index);
        auto saved = thread.checkpoints[checkpoint_id];
        thread.checkpoints[checkpoint_id] = match_state.string_position;
        add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        thread.checkpoints[checkpoint_id] = saved;
        return;
    }
    case NFANode::Type::FailIfEmpty: {
        auto checkpoint_id = static_cast<size_t>(node.data_index);
        if (thread.checkpoints[checkpoint_id] != NumericLimits<size_t>::max()
            && thread.checkpoints[checkpoint_id] == match_state.string_position) {
            return; // Empty match detected — block this thread path
        }
        add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        return;
    }
    case NFANode::Type::SaveModifiers: {
        if (thread.modifier_depth >= MAX_MODIFIER_DEPTH)
            return; // Stack overflow protection
        auto new_modifiers = node.data_index;
        auto current_flags = to_underlying(thread.current_options.value());
        thread.modifier_stack[thread.modifier_depth++] = current_flags;
        auto saved_options = thread.current_options;
        thread.current_options = AllOptions { static_cast<AllFlags>(new_modifiers) };
        add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        thread.current_options = saved_options;
        --thread.modifier_depth;
        return;
    }
    case NFANode::Type::RestoreModifiers: {
        if (thread.modifier_depth == 0)
            return; // Can't restore, thread dies
        auto saved_options = thread.current_options;
        auto previous_modifiers = thread.modifier_stack[--thread.modifier_depth];
        thread.current_options = AllOptions { static_cast<AllFlags>(previous_modifiers) };
        add_thread(list, graph, node.out1, thread, input, match_state, capture_slots);
        thread.current_options = saved_options;
        thread.modifier_stack[thread.modifier_depth++] = previous_modifiers;
        return;
    }
    case NFANode::Type::Match:
    case NFANode::Type::Accept:
        list.add(state, thread);
        return;
    }
}

NFAExecuteResult execute_nfa(
    NFAGraph const& graph,
    FlatByteCode const& bytecode,
    MatchInput const& input,
    MatchState& state)
{
    auto const* data = bytecode.flat_data().data();
    auto num_states = graph.nodes.size();
    auto capture_group_count = state.capture_group_count;
    auto capture_slots = capture_group_count * 2;
    auto checkpoint_slots = graph.checkpoint_count;

    static thread_local NFAThreadList current_list;
    static thread_local NFAThreadList next_list;
    static thread_local Vector<size_t> working_captures;
    static thread_local Vector<size_t> working_checkpoints;
    current_list.init(num_states, capture_slots, checkpoint_slots, state.current_options);
    next_list.init(num_states, capture_slots, checkpoint_slots, state.current_options);
    current_list.clear();
    next_list.clear();
    working_captures.clear_with_capacity();
    working_checkpoints.clear_with_capacity();
    working_captures.resize_and_keep_capacity(capture_slots);
    working_checkpoints.resize_and_keep_capacity(checkpoint_slots);

    // Seed initial thread
    NFAThread initial_thread;
    initial_thread.captures = working_captures.data();
    initial_thread.checkpoints = working_checkpoints.data();
    for (size_t i = 0; i < capture_slots; ++i)
        initial_thread.captures[i] = NumericLimits<size_t>::max();
    for (size_t i = 0; i < checkpoint_slots; ++i)
        initial_thread.checkpoints[i] = NumericLimits<size_t>::max();
    initial_thread.current_options = state.current_options;
    initial_thread.modifier_depth = 0;

    add_thread(current_list, graph, graph.start, initial_thread, input, state, capture_slots);

    // Track the best match found so far
    bool matched = false;
    Vector<size_t> best_captures;
    best_captures.resize(capture_slots);
    size_t best_match_end = 0;
    size_t best_match_end_in_code_units = 0;
    AllOptions best_options = state.current_options;

    auto view_length = input.view.length();

    // Check if the start position already has an accept thread
    for (auto s : current_list.active) {
        if (graph.nodes[s].type == NFANode::Type::Accept) {
            matched = true;
            if (capture_slots > 0)
                memcpy(best_captures.data(), current_list.captures_for(s), capture_slots * sizeof(size_t));
            best_match_end = state.string_position;
            best_match_end_in_code_units = state.string_position_in_code_units;
            best_options = current_list.thread_options[s];
            break;
        }
    }

    while (state.string_position < view_length) {
        if (current_list.active.is_empty())
            break;

        next_list.clear();

        auto code_unit_pos = state.string_position_in_code_units;

        for (auto s : current_list.active) {
            auto const& node = graph.nodes[s];
            if (node.type == NFANode::Type::Accept)
                continue;
            if (node.type != NFANode::Type::Match)
                continue;

            auto const& matcher = graph.matchers[node.data_index];
            auto thread_options = current_list.thread_options[s];

            // Load thread state from flat storage into working buffers
            NFAThread thread;
            thread.captures = working_captures.data();
            thread.checkpoints = working_checkpoints.data();
            current_list.load_thread(s, thread);

            // Try single_char fast path (not safe for Unicode+Insensitive which needs full case folding)
            bool is_unicode_insensitive = (thread_options & AllFlags::Insensitive) && input.view.unicode();
            if (matcher.single_char.has_value() && !is_unicode_insensitive) {
                auto input_ch = input.view.unicode_aware_code_point_at(code_unit_pos);
                auto expected = matcher.single_char.value();
                bool match_ok = false;

                if (thread_options & AllFlags::Insensitive) {
                    match_ok = to_ascii_lowercase(input_ch) == to_ascii_lowercase(expected);
                } else {
                    match_ok = (input_ch == expected);
                }

                if (match_ok) {
                    auto saved_pos = state.string_position;
                    auto saved_code_units = state.string_position_in_code_units;
                    advance_string_position(state, input.view, input_ch);
                    add_thread(next_list, graph, node.out1, thread, input, state, capture_slots);
                    state.string_position = saved_pos;
                    state.string_position_in_code_units = saved_code_units;
                }
            } else {
                auto saved_pos = state.string_position;
                auto saved_code_units = state.string_position_in_code_units;
                state.string_position_before_match = state.string_position;
                state.current_options = thread_options;

                auto match_ip = matcher.bytecode_ip;
                auto opcode_id = static_cast<OpCodeId>(data[match_ip]);

                ExecutionResult result;
                if (opcode_id == OpCodeId::CompareSimple)
                    result = CompareInternals<FlatByteCode, true>::execute_impl(bytecode, data, match_ip, input, state);
                else
                    result = CompareInternals<FlatByteCode, false>::execute_impl(bytecode, data, match_ip, input, state);

                if (result == ExecutionResult::Continue) {
                    add_thread(next_list, graph, node.out1, thread, input, state, capture_slots);
                }
                state.string_position = saved_pos;
                state.string_position_in_code_units = saved_code_units;
            }
        }

        advance_string_position(state, input.view);
        swap(current_list, next_list);

        for (auto s : current_list.active) {
            if (graph.nodes[s].type == NFANode::Type::Accept) {
                matched = true;
                if (capture_slots > 0)
                memcpy(best_captures.data(), current_list.captures_for(s), capture_slots * sizeof(size_t));
                best_match_end = state.string_position;
                best_match_end_in_code_units = state.string_position_in_code_units;
                best_options = current_list.thread_options[s];
                break;
            }
        }
    }

    if (!matched)
        return NFAExecuteResult::DidNotMatch;

    // Populate match state from best thread
    state.string_position = best_match_end;
    state.string_position_in_code_units = best_match_end_in_code_units;
    state.current_options = best_options;

    // Populate capture groups
    if (capture_group_count > 0 && !(input.regex_options.has_flag_set(AllFlags::SkipSubExprResults))) {
        if (input.match_index >= state.capture_group_matches_size()) {
            state.flat_capture_group_matches.ensure_capacity((input.match_index + 1) * state.capture_group_count);
            for (size_t i = state.capture_group_matches_size(); i <= input.match_index; ++i)
                for (size_t j = 0; j < state.capture_group_count; ++j)
                    state.flat_capture_group_matches.append({});
        }

        auto group_span = state.mutable_capture_group_matches(input.match_index);
        for (size_t g = 0; g < capture_group_count; ++g) {
            auto start = best_captures[(g * 2)];
            auto end = best_captures[(g * 2) + 1];
            if (start != NumericLimits<size_t>::max() && end != NumericLimits<size_t>::max() && end >= start) {
                auto length = end - start;
                auto captured_text = input.view.substring_view(start, length);
                auto group_id = static_cast<u32>(g + 1);
                if (auto name_it = graph.named_capture_group_names.find(group_id); name_it != graph.named_capture_group_names.end())
                    group_span[g] = { captured_text, name_it->value, input.line, start, input.global_offset + start };
                else
                    group_span[g] = { captured_text, input.line, start, input.global_offset + start };
            } else {
                group_span[g].reset();
            }
        }
    }

    return NFAExecuteResult::Matched;
}

}
