pub mod regexp_parser;
pub mod exp_optimizer;

#[cfg(test)]
mod tests {
    use crate::regexp_parser::parse_regex_into_expression;
    use crate::exp_optimizer::optimize_expression;

    #[test]
    fn can_parse_regex_into_expression() {
        let expression = parse_regex_into_expression(r#"^((?:https?:)?//)?((?:www|m)\.)?((?:youtube\.com|youtu.be))(/(?:[\w\-]+\?v=|embed/|v/)?)([\w\-]+)(\S+)?$"#).unwrap();
        println!("{}", optimize_expression(&expression));
    }
}
