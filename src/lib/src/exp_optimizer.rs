use regex::Regex;

fn remove_quote_comma_space(input: &str) -> String {
    // Create a regex pattern to match ", "
    let pattern = Regex::new("\", \"").expect("Invalid regex pattern");

    // Replace all occurrences of ", " with an empty string
    let result = pattern.replace_all(input, "");

    // Convert the result to a String and return it
    result.to_string()
}

fn replace_single_arg_concat_with_capture(input: &str) -> String {
    // Create a regex pattern to match content within double quotes
    let pattern = Regex::new(r#"concatenation_of\(("[^,]*")\)"#).expect("Invalid regex pattern");

    // Replace all matches with the captured content
    let result = pattern.replace_all(input, |caps: &regex::Captures| {
        // caps[0] is the entire match, and caps[1] is the content within double quotes
        caps[1].to_string()
    });

    // Convert the result to a String and return it
    result.to_string()
}

pub fn optimize_expression(input: &str) -> String {
    // Remove all occurrences of ", "
    let result = remove_quote_comma_space(input);

    // Replace all occurrences of concatenate("...") with "..."
    let result = replace_single_arg_concat_with_capture(&result);

    // Return the result
    result
}