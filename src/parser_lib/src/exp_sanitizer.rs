use regex::Regex;

fn concatenate_adjacent_unhashed_literals(input: &str) -> String {
    // Create a regex pattern to match (", ")
    let pattern = Regex::new("\"[^#)]?,\\s*[^#]?\"").expect("Invalid regex pattern");

    // Replace all occurrences of ", " with an empty string
    let result = pattern.replace_all(input, "");

    // Convert the result to a String and return it
    result.to_string()
}

fn concatenate_adjacent_hashed_literals(input: &str) -> String {
    // Create a regex pattern to match ("#, #")
    let pattern = Regex::new("\"#{1},\\s*#{1}\"").expect("Invalid regex pattern");

    // Replace all occurrences of ", " with an empty string
    let result = pattern.replace_all(input, "");

    // Convert the result to a String and return it
    result.to_string()
}

fn remove_hash_from_start_of_string(input: &str) -> String {
    // Create a regex pattern to match (#")
    let pattern = Regex::new("#{1}\"").expect("Invalid regex pattern");

    // Replace all occurrences of ", " with an empty string
    let result = pattern.replace_all(input, "\"");

    // Convert the result to a String and return it
    result.to_string()
}

fn remove_hash_from_end_of_string(input: &str) -> String {
    // Create a regex pattern to match ("#)
    let pattern = Regex::new("\"#{1}").expect("Invalid regex pattern");

    // Replace all occurrences of ", " with an empty string
    let result = pattern.replace_all(input, "\"");

    // Convert the result to a String and return it
    result.to_string()
}

    // Replace all occurrences of concatenate("...") with "..."
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

pub fn sanitize_safe_expression(input: &str) -> String {
    let mut result: String;

    result = concatenate_adjacent_unhashed_literals(input);
    result = replace_single_arg_concat_with_capture(&result);

    result
}

pub fn sanitize_unsafe_expression(input: &str) -> String {
    let mut result: String;

    result = concatenate_adjacent_unhashed_literals(input);
    result = concatenate_adjacent_hashed_literals(&result);
    result = remove_hash_from_start_of_string(&result);
    result = remove_hash_from_end_of_string(&result);
    result = replace_single_arg_concat_with_capture(&result);

    result
}