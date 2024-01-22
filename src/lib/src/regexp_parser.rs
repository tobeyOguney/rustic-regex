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
                "greedy_repetitions.zero_or_one_of({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::ZeroOrMore => Ok(format!(
                "greedy_repetitions.zero_or_more_of({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::OneOrMore => Ok(format!(
                "greedy_repetitions.one_or_more_of({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::Range(range) => match range {
                ast::RepetitionRange::Exactly(n) => Ok(format!(
                    "greedy_repetitions.exactly_n_of({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::AtLeast(n) => Ok(format!(
                    "greedy_repetitions.at_least_n_of({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::Bounded(min, max) => Ok(format!(
                    "greedy_repetitions.bounded_instances_of({}, {}, {})",
                    min,
                    max,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
            },
        }
    } else {
        match &repetition.op.kind {
            ast::RepetitionKind::ZeroOrOne => Ok(format!(
                "lazy_repetitions.zero_or_one_of({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::ZeroOrMore => Ok(format!(
                "lazy_repetitions.zero_or_more_of({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::OneOrMore => Ok(format!(
                "lazy_repetitions.one_or_more_of({})",
                &parse_regex_tree_into_expression(&repetition.ast)?
            )),
            ast::RepetitionKind::Range(range) => match range {
                ast::RepetitionRange::Exactly(n) => Ok(format!(
                    "lazy_repetitions.exactly_n_of({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::AtLeast(n) => Ok(format!(
                    "lazy_repetitions.exactly_n_of({}, {})",
                    n,
                    &parse_regex_tree_into_expression(&repetition.ast)?
                )),
                ast::RepetitionRange::Bounded(min, max) => Ok(format!(
                    "lazy_repetitions.bounded_instances_of({}, {}, {})",
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
        "concatenation_of({})",
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
                expression.push_str("flag.negate(), ");
            }
            ast::FlagsItemKind::Flag(flag) => match flag {
                ast::Flag::CaseInsensitive => {
                    expression.push_str("flag.be_case_insensitive(), ");
                }
                ast::Flag::MultiLine => {
                    expression.push_str("flag.enable_multi_line_match(), ");
                }
                ast::Flag::DotMatchesNewLine => {
                    expression.push_str("flag.new_line_becomes_character(), ");
                }
                ast::Flag::SwapGreed => {
                    expression.push_str("flag.swap_greed_modes(), ");
                }
                ast::Flag::Unicode => {
                    expression.push_str("flag.enable_unicode_chars(), ");
                }
                ast::Flag::CRLF => {
                    expression.push_str("flag.enable_crlf(), ");
                }
                ast::Flag::IgnoreWhitespace => {
                    expression.push_str("flag.ignore_whitespace(), ");
                }
            },
        }
    }
    Ok(format!(
        "flags({})",
        expression.trim_end_matches(", ").to_string()
    ))
}

fn get_expression_for_dot() -> Result<String, String> {
    Ok("any_character()".to_string())
}

fn get_expression_for_assertion(assertion: &ast::Assertion) -> Result<String, String> {
    match &assertion.kind {
        ast::AssertionKind::StartLine => Ok("assertion.start_of_line()".to_string()),
        ast::AssertionKind::EndLine => Ok("assertion.end_of_line()".to_string()),
        ast::AssertionKind::StartText => Ok("assertion.start_of_text()".to_string()),
        ast::AssertionKind::EndText => Ok("assertion.end_of_text()".to_string()),
        ast::AssertionKind::WordBoundary => Ok("assertion.word_boundary()".to_string()),
        ast::AssertionKind::NotWordBoundary => Ok("assertion.not_word_boundary()".to_string()),
        ast::AssertionKind::WordBoundaryStart => Ok("assertion.start_of_word_boundary()".to_string()),
        ast::AssertionKind::WordBoundaryEnd => Ok("assertion.end_of_word_boundary()".to_string()),
        ast::AssertionKind::WordBoundaryStartAngle => Ok("assertion.start_angle_of_word_boundary()".to_string()),
        ast::AssertionKind::WordBoundaryEndAngle => Ok("assertion.end_angle_of_word_boundary()".to_string()),
        ast::AssertionKind::WordBoundaryStartHalf => Ok("assertion.start_half_of_word_boundary()".to_string()),
        ast::AssertionKind::WordBoundaryEndHalf => Ok("assertion.end_half_of_word_boundary()".to_string()),
    }
}

fn get_expression_for_class_unicode(class_unicode: &ast::ClassUnicode) -> Result<String, String> {
    if class_unicode.negated {
        match &class_unicode.kind {
            ast::ClassUnicodeKind::OneLetter(letter) => {
                Ok(format!("unicode_character.that_is_not_this_letter(\"{}\")", letter))
            }
            ast::ClassUnicodeKind::Named(name) => Ok(format!("unicode_character.that_is_not_of_this_class(\"{}\")", name)),
            ast::ClassUnicodeKind::NamedValue { op, name, value } => match op {
                ast::ClassUnicodeOpKind::Equal => Ok(format!(
                    "unicode_character.that_does_not_have_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::Colon => Ok(format!(
                    "unicode_character.that_does_not_have_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::NotEqual => Ok(format!(
                    "unicode_character.that_has_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
            },
        }
    } else {
        match &class_unicode.kind {
            ast::ClassUnicodeKind::OneLetter(letter) => {
                Ok(format!("unicode_character.that_is_this_letter(\"{}\")", letter))
            }
            ast::ClassUnicodeKind::Named(name) => Ok(format!("unicode_character.that_is_of_this_class(\"{}\")", name)),
            ast::ClassUnicodeKind::NamedValue { op, name, value } => match op {
                ast::ClassUnicodeOpKind::Equal => Ok(format!(
                    "unicode_character.that_has_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::Colon => Ok(format!(
                    "unicode_character.that_has_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
                ast::ClassUnicodeOpKind::NotEqual => Ok(format!(
                    "unicode_character.that_does_not_have_property_with_specified_value(\"{}\", \"{}\")",
                    name, value
                )),
            },
        }
    }
}

fn get_expression_for_class_perl(class_perl: &ast::ClassPerl) -> Result<String, String> {
    if class_perl.negated {
        match &class_perl.kind {
            ast::ClassPerlKind::Digit => Ok("perl_character_descriptor.not_digit()".to_string()),
            ast::ClassPerlKind::Space => Ok("perl_character_descriptor.not_whitespace()".to_string()),
            ast::ClassPerlKind::Word => Ok("perl_character_descriptor.not_word()".to_string()),
        }
    } else {
        match &class_perl.kind {
            ast::ClassPerlKind::Digit => Ok("perl_character_descriptor.digit()".to_string()),
            ast::ClassPerlKind::Space => Ok("perl_character_descriptor.whitespace()".to_string()),
            ast::ClassPerlKind::Word => Ok("perl_character_descriptor.word()".to_string()),
        }
    }
}

fn get_expression_for_ascii(ascii: &ast::ClassAscii) -> Result<String, String> {
    if ascii.negated {
        match ascii.kind {
            ast::ClassAsciiKind::Alnum => Ok("ascii_character.that_is_not_alphanumeric()".to_string()),
            ast::ClassAsciiKind::Alpha => Ok("ascii_character.that_is_not_alphabetic()".to_string()),
            ast::ClassAsciiKind::Ascii => Ok("ascii_character.not_any()".to_string()),
            ast::ClassAsciiKind::Blank => Ok("ascii_character.that_is_not_blank()".to_string()),
            ast::ClassAsciiKind::Cntrl => Ok("ascii_character.that_is_not_control()".to_string()),
            ast::ClassAsciiKind::Digit => Ok("ascii_character.that_is_not_digit()".to_string()),
            ast::ClassAsciiKind::Graph => Ok("ascii_character.that_is_not_graph()".to_string()),
            ast::ClassAsciiKind::Lower => Ok("ascii_character.that_is_not_lowercase()".to_string()),
            ast::ClassAsciiKind::Print => Ok("ascii_character.that_is_not_printable()".to_string()),
            ast::ClassAsciiKind::Punct => Ok("ascii_character.that_is_not_punctuation()".to_string()),
            ast::ClassAsciiKind::Space => Ok("ascii_character.that_is_not_whitespace()".to_string()),
            ast::ClassAsciiKind::Upper => Ok("ascii_character.that_is_not_uppercase()".to_string()),
            ast::ClassAsciiKind::Word => Ok("ascii_character.that_is_not_word()".to_string()),
            ast::ClassAsciiKind::Xdigit => Ok("ascii_character.that_is_not_hex_digit()".to_string()),
        }
    } else {
        match ascii.kind {
            ast::ClassAsciiKind::Alnum => Ok("ascii_character.that_is_alphanumeric()".to_string()),
            ast::ClassAsciiKind::Alpha => Ok("ascii_character.that_is_alphabetic()".to_string()),
            ast::ClassAsciiKind::Ascii => Ok("ascii_character.any()".to_string()),
            ast::ClassAsciiKind::Blank => Ok("ascii_character.that_is_blank()".to_string()),
            ast::ClassAsciiKind::Cntrl => Ok("ascii_character.that_is_control()".to_string()),
            ast::ClassAsciiKind::Digit => Ok("ascii_character.that_is_digit()".to_string()),
            ast::ClassAsciiKind::Graph => Ok("ascii_character.that_is_graph()".to_string()),
            ast::ClassAsciiKind::Lower => Ok("ascii_character.that_is_lowercase()".to_string()),
            ast::ClassAsciiKind::Print => Ok("ascii_character.that_is_printable()".to_string()),
            ast::ClassAsciiKind::Punct => Ok("ascii_character.that_is_punctuation()".to_string()),
            ast::ClassAsciiKind::Space => Ok("ascii_character.that_is_whitespace()".to_string()),
            ast::ClassAsciiKind::Upper => Ok("ascii_character.that_is_uppercase()".to_string()),
            ast::ClassAsciiKind::Word => Ok("ascii_character.that_is_word()".to_string()),
            ast::ClassAsciiKind::Xdigit => Ok("ascii_character.that_is_hex_digit()".to_string()),
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
        Ok(format!("negated_group({})", get_expression_for_class_set(&class_bracketed.kind)?))
    } else {
        Ok(format!("group({})", get_expression_for_class_set(&class_bracketed.kind)?))
    }
}

fn get_expression_for_group(group: &ast::Group) -> Result<String, String> {
    match &group.kind {
        ast::GroupKind::CaptureIndex(_) => Ok(format!(
            "capture_group.by_index({})",
            &parse_regex_tree_into_expression(&group.ast)?
        )),
        ast::GroupKind::CaptureName { name, starts_with_p } => {
            if *starts_with_p {
                Ok(format!(
                    "capture_group.by_name_with_p_prefix(\"{}\", {})",
                    name.name,
                    &parse_regex_tree_into_expression(&group.ast)?
                ))
            } else {
                Ok(format!(
                    "capture_group.by_name(\"{}\", {})",
                    name.name,
                    &parse_regex_tree_into_expression(&group.ast)?
                ))
            }
        }
        ast::GroupKind::NonCapturing(flags) => Ok(format!(
            "group_with_flags({}, {})",
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
