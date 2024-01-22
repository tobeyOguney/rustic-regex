use fancy_regex::{Assertion, Expr, LookAround};

fn get_expression_for_empty() -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_any(newline: bool) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_assertion(assertion: &Assertion) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_literal(val: &str, casei: bool) -> Result<String, String> {
    Ok(val.to_string())
}

fn get_expression_for_group(group: &Expr) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_concat(concat: &Vec<Expr>) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_alt(alt: &Vec<Expr>) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_repeat(
    child: &Expr,
    lo: usize,
    hi: usize,
    greedy: bool,
) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_lookaround(ast: &Expr, lookaround: &LookAround) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_delegate(inner: &String, size: usize, casei: bool) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_backref(index: usize) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_atomic_group(ast: &Expr) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_keep_out() -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_continue_from_previous_match_end() -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_backref_exists_condition(index: usize) -> Result<String, String> {
    Ok("".to_string())
}

fn get_expression_for_conditional(
    condition: &Expr,
    true_branch: &Expr,
    false_branch: &Expr,
) -> Result<String, String> {
    Ok("".to_string())
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
        Expr::Delegate { inner, size, casei } => get_expression_for_delegate(inner, *size, *casei),
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
    parse_regex_tree_into_expression(&ast)
}
