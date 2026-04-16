def generate_ai_summary(text: str) -> str:
    try:
        from transformers import pipeline
    except ModuleNotFoundError as e:
        return f"AI summary unavailable: missing dependency -> {e}"

    generator = pipeline("text-generation", model="distilgpt2")
    prompt = (
        "Summarize these cloud security findings for an executive audience. "
        "Keep it short, specific, and action-oriented.\n\n"
        f"{text}\n\nExecutive summary:"
    )
    result = generator(prompt, max_new_tokens=120, do_sample=False)
    return result[0]["generated_text"]
