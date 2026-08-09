struct AnthropicRequestDto;

fn select_policy(provider_name: &str) -> &'static str {
    match provider_name {
        "openai" => "responses-policy",
        "anthropic" => "messages-policy",
        _ => "default-policy",
    }
}
