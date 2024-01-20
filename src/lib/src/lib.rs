pub mod regexp_parser;

#[cfg(test)]
mod tests {
    use crate::regexp_parser::parse_regex_into_expression;


    #[test]
    fn can_parse_regex_into_expression() {
        println!("{}", parse_regex_into_expression("a|b").unwrap());
    }
}
