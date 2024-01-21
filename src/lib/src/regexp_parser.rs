use regex_syntax::ast::{self, parse::Parser, Ast};

fn get_expression_for_empty() -> Result<String, String> {
    Ok("empty()".to_string())
}

fn get_expression_for_literal(literal: &ast::Literal) -> Result<String, String> {
    Ok(format!("\"{}\"", literal.c))
}

fn get_expression_for_repetition(repetition: &ast::Repetition) -> Result<String, String> {
    if repetition.greedy {
        match &repetition.op.kind {
            ast::RepetitionKind::ZeroOrOne => Ok(format!(
                "zero_or_one_greedy_repetitions({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::ZeroOrMore => Ok(format!(
                "zero_or_more_greedy_repetitions({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::OneOrMore => Ok(format!(
                "one_or_more_greedy_repetitions({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::Range(range) => match range {
                ast::RepetitionRange::Exactly(n) => Ok(format!(
                    "exactly_n_greedy_repetitions({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::AtLeast(n) => Ok(format!(
                    "at_least_n_greedy_repetitions({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::Bounded(min, max) => Ok(format!(
                    "bounded_greedy_repetitions({}, {}, {})",
                    min,
                    max,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
            },
        }
    } else {
        match &repetition.op.kind {
            ast::RepetitionKind::ZeroOrOne => Ok(format!(
                "zero_or_one_lazy_repetitions({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::ZeroOrMore => Ok(format!(
                "zero_or_more_lazy_repetitions({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::OneOrMore => Ok(format!(
                "one_or_more_lazy_repetitions({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::Range(range) => match range {
                ast::RepetitionRange::Exactly(n) => Ok(format!(
                    "exactly_n_lazy_repetitions({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::AtLeast(n) => Ok(format!(
                    "at_least_n_lazy_repetitions({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::Bounded(min, max) => Ok(format!(
                    "bounded_lazy_repetitions({}, {}, {})",
                    min,
                    max,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
            },
        }
    }
}

fn get_expression_for_concat(node: &Box<ast::Concat>) -> Result<String, String> {
    let mut expression = String::new();
    for ast in &node.asts {
        expression.push_str(&parse_regex_tree_into_expression(ast)?);
        expression.push_str(", ");
    }
    Ok(format!(
        "concatenate({})",
        expression.trim_end_matches(", ").to_string()
    ))
}

fn get_expression_for_alternation(node: &Box<ast::Alternation>) -> Result<String, String> {
    let mut expression = String::new();
    for ast in &node.asts {
        expression.push_str(&parse_regex_tree_into_expression(&ast)?);
        expression.push_str(", ");
    }
    Ok(format!(
        "any_of({})",
        expression.trim_end_matches(", ").to_string()
    ))
}

fn get_expression_for_flags(flags: &ast::Flags) -> Result<String, String> {
    let mut expression = String::new();
    for flag in &flags.items {
        match flag.kind {
            ast::FlagsItemKind::Negation => {
                expression.push_str("negate(), ");
            }
            ast::FlagsItemKind::Flag(flag) => match flag {
                ast::Flag::CaseInsensitive => {
                    expression.push_str("be_case_insensitive(), ");
                }
                ast::Flag::MultiLine => {
                    expression.push_str("enable_multi_line_match(), ");
                }
                ast::Flag::DotMatchesNewLine => {
                    expression.push_str("new_line_becomes_character(), ");
                }
                ast::Flag::SwapGreed => {
                    expression.push_str("swap_greed_modes(), ");
                }
                ast::Flag::Unicode => {
                    expression.push_str("enable_unicode_chars(), ");
                }
                ast::Flag::CRLF => {
                    expression.push_str("enable_crlf(), ");
                }
                ast::Flag::IgnoreWhitespace => {
                    expression.push_str("ignore_whitespace(), ");
                }
            },
        }
    }
    Ok(format!(
        "flag_group({})",
        expression.trim_end_matches(", ").to_string()
    ))
}

fn get_expression_for_dot() -> Result<String, String> {
    Ok("any_character()".to_string())
}

fn get_expression_for_assertion(assertion: &ast::Assertion) -> Result<String, String> {
    match &assertion.kind {
        ast::AssertionKind::StartLine => Ok("is_start_of_line()".to_string()),
        ast::AssertionKind::EndLine => Ok("is_end_of_line()".to_string()),
        ast::AssertionKind::StartText => Ok("is_start_of_text()".to_string()),
        ast::AssertionKind::EndText => Ok("is_end_of_text()".to_string()),
        ast::AssertionKind::WordBoundary => Ok("is_word_boundary()".to_string()),
        ast::AssertionKind::NotWordBoundary => Ok("is_not_word_boundary()".to_string()),
        ast::AssertionKind::WordBoundaryStart => Ok("is_word_boundary_start()".to_string()),
        ast::AssertionKind::WordBoundaryEnd => Ok("is_word_boundary_end()".to_string()),
        ast::AssertionKind::WordBoundaryStartAngle => Ok("is_word_boundary_start_angle()".to_string()),
        ast::AssertionKind::WordBoundaryEndAngle => Ok("is_word_boundary_end_angle()".to_string()),
        ast::AssertionKind::WordBoundaryStartHalf => Ok("is_word_boundary_start_half()".to_string()),
        ast::AssertionKind::WordBoundaryEndHalf => Ok("is_word_boundary_end_half()".to_string()),
    }
}

fn get_expression_for_class_unicode(class_unicode: &ast::ClassUnicode) -> Result<String, String> {
    if class_unicode.negated {
        match &class_unicode.kind {
            ast::ClassUnicodeKind::OneLetter(letter) => {
                Ok(format!("not_this_unicode_letter(\"{}\")", letter))
            }
            ast::ClassUnicodeKind::Named(name) => Ok(format!("not_this_unicode_class(\"{}\")", name)),
            ast::ClassUnicodeKind::NamedValue { op, name, value } => match op {
                ast::ClassUnicodeOpKind::Equal => Ok(format!(
                    "doesnt_have_unicode_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::Colon => Ok(format!(
                    "doesnt_have_unicode_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::NotEqual => Ok(format!(
                    "doesnt_have_unicode_property_without_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
            },
        }
    } else {
        match &class_unicode.kind {
            ast::ClassUnicodeKind::OneLetter(letter) => {
                Ok(format!("is_this_unicode_letter(\"{}\")", letter))
            }
            ast::ClassUnicodeKind::Named(name) => Ok(format!("is_this_unicode_class(\"{}\")", name)),
            ast::ClassUnicodeKind::NamedValue { op, name, value } => match op {
                ast::ClassUnicodeOpKind::Equal => Ok(format!(
                    "has_unicode_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::NotEqual => Ok(format!(
                    "has_unicode_property_without_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::Colon => Ok(format!(
                    "has_unicode_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
            },
        }
    }
}

fn get_expression_for_class_perl(class_perl: &ast::ClassPerl) -> Result<String, String> {
    if class_perl.negated {
        match &class_perl.kind {
            ast::ClassPerlKind::Digit => Ok("is_not_a_digit()".to_string()),
            ast::ClassPerlKind::Space => Ok("is_not_whitespace()".to_string()),
            ast::ClassPerlKind::Word => Ok("is_not_a_word()".to_string()),
        }
    } else {
        match &class_perl.kind {
            ast::ClassPerlKind::Digit => Ok("is_a_digit()".to_string()),
            ast::ClassPerlKind::Space => Ok("is_whitespace()".to_string()),
            ast::ClassPerlKind::Word => Ok("is_a_word()".to_string()),
        }
    }
}

fn get_expression_for_ascii(ascii: &ast::ClassAscii) -> Result<String, String> {
    if ascii.negated {
        match ascii.kind {
            ast::ClassAsciiKind::Alnum => Ok("is_not_alphanumeric_ascii()".to_string()),
            ast::ClassAsciiKind::Alpha => Ok("is_not_alphabetic_ascii()".to_string()),
            ast::ClassAsciiKind::Ascii => Ok("is_not_ascii()".to_string()),
            ast::ClassAsciiKind::Blank => Ok("is_not_blank_ascii()".to_string()),
            ast::ClassAsciiKind::Cntrl => Ok("is_not_control_ascii()".to_string()),
            ast::ClassAsciiKind::Digit => Ok("is_not_digit_ascii()".to_string()),
            ast::ClassAsciiKind::Graph => Ok("is_not_graph_ascii()".to_string()),
            ast::ClassAsciiKind::Lower => Ok("is_not_lowercase_ascii()".to_string()),
            ast::ClassAsciiKind::Print => Ok("is_not_printable_ascii()".to_string()),
            ast::ClassAsciiKind::Punct => Ok("is_not_punctuation_ascii()".to_string()),
            ast::ClassAsciiKind::Space => Ok("is_not_whitespace_ascii()".to_string()),
            ast::ClassAsciiKind::Upper => Ok("is_not_uppercase_ascii()".to_string()),
            ast::ClassAsciiKind::Word => Ok("is_not_word_ascii()".to_string()),
            ast::ClassAsciiKind::Xdigit => Ok("is_not_hex_digit_ascii()".to_string()),
        }
    } else {
        match ascii.kind {
            ast::ClassAsciiKind::Alnum => Ok("is_alphanumeric_ascii()".to_string()),
            ast::ClassAsciiKind::Alpha => Ok("is_alphabetic_ascii()".to_string()),
            ast::ClassAsciiKind::Ascii => Ok("is_ascii()".to_string()),
            ast::ClassAsciiKind::Blank => Ok("is_blank_ascii()".to_string()),
            ast::ClassAsciiKind::Cntrl => Ok("is_control_ascii()".to_string()),
            ast::ClassAsciiKind::Digit => Ok("is_digit_ascii()".to_string()),
            ast::ClassAsciiKind::Graph => Ok("is_graph_ascii()".to_string()),
            ast::ClassAsciiKind::Lower => Ok("is_lowercase_ascii()".to_string()),
            ast::ClassAsciiKind::Print => Ok("is_printable_ascii()".to_string()),
            ast::ClassAsciiKind::Punct => Ok("is_punctuation_ascii()".to_string()),
            ast::ClassAsciiKind::Space => Ok("is_whitespace_ascii()".to_string()),
            ast::ClassAsciiKind::Upper => Ok("is_uppercase_ascii()".to_string()),
            ast::ClassAsciiKind::Word => Ok("is_word_ascii()".to_string()),
            ast::ClassAsciiKind::Xdigit => Ok("is_hex_digit_ascii()".to_string()),
        }
    }
}

fn get_expression_for_class_set_union(class_set_union: &ast::ClassSetUnion) -> Result<String, String> {
    let mut expression = String::new();
    for class_set_item in &class_set_union.items {
        expression.push_str(&get_expression_for_class_set(
            &ast::ClassSet::Item(class_set_item.clone()),
        )?);
        expression.push_str(", ");
    }
    Ok(format!(
        "any_of({})",
        expression.trim_end_matches(", ").to_string()
    ))
}

fn get_expression_for_class_set(class_set: &ast::ClassSet) -> Result<String, String> {
    match class_set {
        ast::ClassSet::Item(item) => match item {
            ast::ClassSetItem::Empty(_) => {
                Ok("empty_item()".to_string())
            }
            ast::ClassSetItem::Literal(literal) => {
                Ok(get_expression_for_literal(literal)?)
            }
            ast::ClassSetItem::Range(range) => {
                Ok(format!("literals_between('{}', '{}')", range.start.c, range.end.c))
            }
            ast::ClassSetItem::Ascii(ascii) => {
                Ok(get_expression_for_ascii(ascii)?)
            }
            ast::ClassSetItem::Unicode(unicode) => {
                Ok(get_expression_for_class_unicode(unicode)?)
            }
            ast::ClassSetItem::Perl(perl) => {
                Ok(get_expression_for_class_perl(perl)?)
            }
            ast::ClassSetItem::Bracketed(bracketed) => {
                Ok(get_expression_for_class_bracketed(bracketed)?)
            }
            ast::ClassSetItem::Union(union) => {
                Ok(get_expression_for_class_set_union(union)?)
            }
        }
        ast::ClassSet::BinaryOp(binary_op) => match binary_op.kind {
            ast::ClassSetBinaryOpKind::Intersection => Ok(format!(
                "intersection_of({}, {})",
                &get_expression_for_class_set(&binary_op.lhs)?,
                &get_expression_for_class_set(&binary_op.rhs)?
            )),
            ast::ClassSetBinaryOpKind::Difference => Ok(format!(
                "difference_of({}, {})",
                &get_expression_for_class_set(&binary_op.lhs)?,
                &get_expression_for_class_set(&binary_op.rhs)?
            )),
            ast::ClassSetBinaryOpKind::SymmetricDifference => Ok(format!(
                "symmetric_difference_of({}, {})",
                &get_expression_for_class_set(&binary_op.lhs)?,
                &get_expression_for_class_set(&binary_op.rhs)?
            )),
        }
    }
}

fn get_expression_for_class_bracketed(
    class_bracketed: &ast::ClassBracketed,
) -> Result<String, String> {
    if class_bracketed.negated {
        Ok(format!("negated_bracket({})", get_expression_for_class_set(&class_bracketed.kind)?))
    } else {
        Ok(format!("bracket({})", get_expression_for_class_set(&class_bracketed.kind)?))
    }
}

fn get_expression_for_group(group: &ast::Group) -> Result<String, String> {
    match &group.kind {
        ast::GroupKind::CaptureIndex(_) => Ok(format!(
            "capture_expression_by_index({})",
            &parse_regex_tree_into_expression(&group.ast)?
        )),
        ast::GroupKind::CaptureName { name, starts_with_p } => {
            if *starts_with_p {
                Ok(format!(
                    "capture_expression_by_name_with_p(\"{}\", {})",
                    name.name,
                    &parse_regex_tree_into_expression(&group.ast)?
                ))
            } else {
                Ok(format!(
                    "capture_expression_by_name(\"{}\", {})",
                    name.name,
                    &parse_regex_tree_into_expression(&group.ast)?
                ))
            }
        }
        ast::GroupKind::NonCapturing(flags) => Ok(format!(
            "non_capturing_expression_with_flags({}, {})",
            &get_expression_for_flags(&flags)?,
            &parse_regex_tree_into_expression(&group.ast)?
        )),
    }
}

fn parse_regex_tree_into_expression(ast: &Ast) -> Result<String, String> {
    match ast {
        Ast::Empty(_) => get_expression_for_empty(),
        Ast::Flags(set_flags) => get_expression_for_flags(&set_flags.flags),
        Ast::Literal(literal) => get_expression_for_literal(literal),
        Ast::Dot(_) => get_expression_for_dot(),
        Ast::Assertion(assertion) => get_expression_for_assertion(assertion),
        Ast::ClassUnicode(class_unicode) => get_expression_for_class_unicode(class_unicode),
        Ast::ClassPerl(class_perl) => get_expression_for_class_perl(class_perl),
        Ast::ClassBracketed(class_bracketed) => get_expression_for_class_bracketed(class_bracketed),
        Ast::Repetition(repetition) => get_expression_for_repetition(repetition),
        Ast::Group(group) => get_expression_for_group(group),
        Ast::Alternation(alternation) => get_expression_for_alternation(alternation),
        Ast::Concat(concat) => get_expression_for_concat(concat),
    }
}

/// Parse a regex string into a regex syntax tree.
fn parse_regex_into_tree(regex: &str) -> Result<Ast, String> {
    let mut parser = Parser::new();
    parser
        .parse(regex)
        .map_err(|e| format!("Failed to parse regex: {}", e))
}

pub fn parse_regex_into_expression(regex: &str) -> Result<String, String> {
    let ast = parse_regex_into_tree(regex)?;
    parse_regex_tree_into_expression(&ast)
}
