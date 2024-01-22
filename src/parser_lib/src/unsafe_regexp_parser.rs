use crate::{exp_sanitizer::sanitize_unsafe_expression, safe_regexp_parser};
use fancy_regex::{Assertion, Expr, LookAround};

fn get_expression_for_empty() -> Result<String, String> {
    Ok("empty()".to_string())
}

fn get_expression_for_any(newline: bool) -> Result<String, String> {
    if newline {
        Ok("any_character_or_newline()".to_string())
    } else {
        Ok("any_character()".to_string())
    }
}

fn get_expression_for_assertion(assertion: &Assertion) -> Result<String, String> {
    match assertion {
        Assertion::StartLine { crlf } => {
            if *crlf {
                Ok("assertion.start_of_line_crlf()".to_string())
            } else {
                Ok("assertion.start_of_line()".to_string())
            }
        }
        Assertion::EndLine { crlf } => {
            if *crlf {
                Ok("assertion.end_of_line_crlf()".to_string())
            } else {
                Ok("assertion.end_of_line()".to_string())
            }
        }
        Assertion::StartText => Ok("assertion.start_of_text()".to_string()),
        Assertion::EndText => Ok("assertion.end_of_text()".to_string()),
        Assertion::WordBoundary => Ok("assertion.word_boundary()".to_string()),
        Assertion::NotWordBoundary => Ok("assertion.not_word_boundary()".to_string()),
        Assertion::LeftWordBoundary => Ok("assertion.left_word_boundary()".to_string()),
        Assertion::RightWordBoundary => Ok("assertion.right_word_boundary()".to_string()),
    }
}

fn get_expression_for_literal(val: &str, casei: bool) -> Result<String, String> {
    if casei {
        Ok(format!("i#\"{}\"#", val))
    } else {
        Ok(format!("\"{}\"", val))
    }
}

fn get_expression_for_group(group: &Expr) -> Result<String, String> {
    Ok(format!(
        "group.capturable({})",
        parse_regex_tree_into_expression(group)?
    ))
}

fn get_expression_for_concat(concat: &Vec<Expr>) -> Result<String, String> {
    Ok(format!(
        "concatenation_of({})",
        concat
            .iter()
            .map(|ast| parse_regex_tree_into_expression(ast))
            .collect::<Result<Vec<String>, String>>()?
            .join(", ")
    ))
}

fn get_expression_for_alt(alt: &Vec<Expr>) -> Result<String, String> {
    Ok(format!(
        "any_of({})",
        alt.iter()
            .map(|ast| parse_regex_tree_into_expression(ast))
            .collect::<Result<Vec<String>, String>>()?
            .join(", ")
    ))
}

fn get_expression_for_repeat(
    child: &Expr,
    lo: usize,
    hi: usize,
    greedy: bool,
) -> Result<String, String> {
    if greedy {
        if lo == 0 && hi == 1 {
            Ok(format!(
                "greedy_repetitions.zero_or_one_of({})",
                parse_regex_tree_into_expression(child)?
            ))
        } else if lo == 0 && hi == usize::MAX {
            Ok(format!(
                "greedy_repetitions.zero_or_more_of({})",
                parse_regex_tree_into_expression(child)?
            ))
        } else if lo == 1 && hi == usize::MAX {
            Ok(format!(
                "greedy_repetitions.one_or_more_of({})",
                parse_regex_tree_into_expression(child)?
            ))
        } else if lo == hi {
            Ok(format!(
                "greedy_repetitions.exactly_n_of({}, {})",
                lo,
                parse_regex_tree_into_expression(child)?
            ))
        } else if hi == usize::MAX {
            Ok(format!(
                "greedy_repetitions.at_least_n_of({}, {})",
                lo,
                parse_regex_tree_into_expression(child)?
            ))
        } else {
            Ok(format!(
                "greedy_repetitions.bounded_instances_of({}, {}, {})",
                lo,
                hi,
                parse_regex_tree_into_expression(child)?
            ))
        }
    } else {
        if lo == 0 && hi == 1 {
            Ok(format!(
                "lazy_repetitions.zero_or_one_of({})",
                parse_regex_tree_into_expression(child)?
            ))
        } else if lo == 0 && hi == usize::MAX {
            Ok(format!(
                "lazy_repetitions.zero_or_more_of({})",
                parse_regex_tree_into_expression(child)?
            ))
        } else if lo == 1 && hi == usize::MAX {
            Ok(format!(
                "lazy_repetitions.one_or_more_of({})",
                parse_regex_tree_into_expression(child)?
            ))
        } else if lo == hi {
            Ok(format!(
                "lazy_repetitions.exactly_n_of({}, {})",
                lo,
                parse_regex_tree_into_expression(child)?
            ))
        } else if hi == usize::MAX {
            Ok(format!(
                "lazy_repetitions.at_least_n_of({}, {})",
                lo,
                parse_regex_tree_into_expression(child)?
            ))
        } else {
            Ok(format!(
                "lazy_repetitions.bounded_instances_of({}, {}, {})",
                lo,
                hi,
                parse_regex_tree_into_expression(child)?
            ))
        }
    }
}

fn get_expression_for_lookaround(ast: &Expr, lookaround: &LookAround) -> Result<String, String> {
    match lookaround {
        LookAround::LookAhead => Ok(format!(
            "lookaround.is_ahead({})",
            parse_regex_tree_into_expression(ast)?
        )),
        LookAround::LookBehind => Ok(format!(
            "lookaround.is_behind({})",
            parse_regex_tree_into_expression(ast)?
        )),
        LookAround::LookAheadNeg => Ok(format!(
            "lookaround.is_not_ahead({})",
            parse_regex_tree_into_expression(ast)?
        )),
        LookAround::LookBehindNeg => Ok(format!(
            "lookaround.is_not_behind({})",
            parse_regex_tree_into_expression(ast)?
        )),
    }
}

fn get_expression_for_delegate(inner: &String, casei: bool) -> Result<String, String> {
    if casei {
        Ok(format!(
            "safe_subexpression.case_insensitive({})",
            safe_regexp_parser::parse_regex_into_expression(inner)?
        ))
    } else {
        Ok(format!(
            "safe_subexpression.case_sensitive({})",
            safe_regexp_parser::parse_regex_into_expression(inner)?
        ))
    }
}

fn get_expression_for_backref(index: usize) -> Result<String, String> {
    Ok(format!("backreference_group_with_index({})", index))
}

fn get_expression_for_atomic_group(ast: &Expr) -> Result<String, String> {
    Ok(format!(
        "group.non_capturable({})",
        parse_regex_tree_into_expression(ast)?
    ))
}

fn get_expression_for_keep_out() -> Result<String, String> {
    Ok("exclude_lhs_from_overall_match()".to_string())
}

fn get_expression_for_continue_from_previous_match_end() -> Result<String, String> {
    Ok("assertion.start_of_line_after_lhs()".to_string())
}

fn get_expression_for_backref_exists_condition(index: usize) -> Result<String, String> {
    Ok(format!(
        "assertion.capturable_group_with_index_exists({})",
        index
    ))
}

fn get_expression_for_conditional(
    condition: &Expr,
    true_branch: &Expr,
    false_branch: &Expr,
) -> Result<String, String> {
    Ok(format!(
        "conditional_expression({}, {}, {})",
        parse_regex_tree_into_expression(condition)?,
        parse_regex_tree_into_expression(true_branch)?,
        parse_regex_tree_into_expression(false_branch)?
    ))
}

fn parse_regex_tree_into_expression(ast: &Expr) -> Result<String, String> {
    match ast {
        Expr::Empty => get_expression_for_empty(),
        Expr::Any { newline } => get_expression_for_any(*newline),
        Expr::Assertion(assertion) => get_expression_for_assertion(assertion),
        Expr::Literal { val, casei } => get_expression_for_literal(val, *casei),
        Expr::Group(group) => get_expression_for_group(group),
        Expr::Concat(concat) => get_expression_for_concat(concat),
        Expr::Alt(alt) => get_expression_for_alt(alt),
        Expr::Repeat {
            child,
            lo,
            hi,
            greedy,
        } => get_expression_for_repeat(child, *lo, *hi, *greedy),
        Expr::LookAround(ast, lookaround) => get_expression_for_lookaround(ast, lookaround),
        Expr::Delegate { inner, casei, .. } => get_expression_for_delegate(inner, *casei),
        Expr::Backref(index) => get_expression_for_backref(*index),
        Expr::AtomicGroup(ast) => get_expression_for_atomic_group(ast),
        Expr::KeepOut => get_expression_for_keep_out(),
        Expr::ContinueFromPreviousMatchEnd => get_expression_for_continue_from_previous_match_end(),
        Expr::BackrefExistsCondition(index) => get_expression_for_backref_exists_condition(*index),
        Expr::Conditional {
            condition,
            true_branch,
            false_branch,
        } => get_expression_for_conditional(condition, true_branch, false_branch),
    }
}

fn parse_regex_into_tree(regex: &str) -> Result<Expr, String> {
    Ok(Expr::parse_tree(regex)
        .map_err(|e| format!("Failed to parse regex: {}", e))
        .unwrap()
        .expr)
}

pub fn parse_regex_into_expression(regex: &str) -> Result<String, String> {
    let ast = parse_regex_into_tree(regex)?;
    let expression = parse_regex_tree_into_expression(&ast)?;
    Ok(sanitize_unsafe_expression(&expression))
}
