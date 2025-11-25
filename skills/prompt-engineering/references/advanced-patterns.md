# Prompt Engineering Advanced Patterns

## Chain-of-Thought Prompting

```python
class ChainOfThoughtBuilder:
    """Build prompts that encourage step-by-step reasoning."""

    def build_cot_prompt(self, task: str) -> str:
        """Build chain-of-thought prompt."""
        return f"""Task: {task}

Let's approach this step by step:

1. First, I'll understand what's being asked
2. Then, I'll identify the key components
3. Next, I'll reason through each part
4. Finally, I'll provide the answer

Step 1: Understanding the task
"""

    def build_self_consistency(self, task: str, num_paths: int = 3) -> list[str]:
        """Generate multiple reasoning paths for self-consistency."""
        prompts = []
        for i in range(num_paths):
            prompts.append(f"""Task: {task}

Reasoning path {i+1}:
Let me think about this differently...

""")
        return prompts
```

## Few-Shot Learning

```python
class FewShotBuilder:
    """Build few-shot prompts with examples."""

    def __init__(self):
        self.examples = {}

    def add_example(self, task_type: str, input_text: str, output: str):
        """Add example for few-shot learning."""
        if task_type not in self.examples:
            self.examples[task_type] = []
        self.examples[task_type].append({
            "input": input_text,
            "output": output
        })

    def build_prompt(self, task_type: str, user_input: str) -> str:
        """Build few-shot prompt with examples."""
        examples = self.examples.get(task_type, [])[:3]  # Max 3 examples

        prompt = "Here are some examples:\n\n"

        for i, ex in enumerate(examples):
            prompt += f"Example {i+1}:\n"
            prompt += f"Input: {ex['input']}\n"
            prompt += f"Output: {ex['output']}\n\n"

        prompt += f"Now, process this:\nInput: {user_input}\nOutput:"

        return prompt

# Usage
builder = FewShotBuilder()
builder.add_example(
    "intent_classification",
    "What's the weather like?",
    "weather"
)
builder.add_example(
    "intent_classification",
    "Turn on the living room lights",
    "home_control"
)
```

## Structured Output Prompting

```python
class StructuredOutputBuilder:
    """Build prompts for structured JSON output."""

    def build_json_prompt(self, task: str, schema: dict) -> str:
        """Build prompt requesting JSON output."""
        import json

        schema_str = json.dumps(schema, indent=2)

        return f"""Task: {task}

Respond with ONLY valid JSON matching this schema:
{schema_str}

Important:
- Output ONLY the JSON, no explanations
- Ensure all required fields are present
- Use null for unknown values
"""

    def build_constrained_prompt(
        self,
        task: str,
        options: list[str]
    ) -> str:
        """Build prompt with constrained options."""
        options_str = ", ".join(f'"{o}"' for o in options)

        return f"""Task: {task}

Respond with ONLY one of these options: {options_str}

Your response must be exactly one of the listed options, nothing else."""
```

## Context Window Optimization

```python
class ContextOptimizer:
    """Optimize context for token efficiency."""

    def __init__(self, max_tokens: int = 4096):
        self.max_tokens = max_tokens

    def optimize_history(
        self,
        history: list[dict],
        current_prompt: str
    ) -> list[dict]:
        """Optimize conversation history to fit context."""

        # Reserve tokens for response
        available = self.max_tokens - 1000

        # Always keep system message and latest exchange
        optimized = []
        if history and history[0]["role"] == "system":
            optimized.append(history[0])
            history = history[1:]

        # Add messages from newest to oldest until limit
        current_tokens = self._count_tokens(current_prompt)
        for msg in reversed(history):
            msg_tokens = self._count_tokens(msg["content"])
            if current_tokens + msg_tokens > available:
                break
            optimized.insert(1 if optimized else 0, msg)
            current_tokens += msg_tokens

        return optimized

    def summarize_context(self, long_context: str, max_length: int = 500) -> str:
        """Summarize long context to save tokens."""
        if len(long_context) <= max_length:
            return long_context

        # Simple truncation with indicator
        return long_context[:max_length] + "\n[Context truncated...]"

    def _count_tokens(self, text: str) -> int:
        """Estimate token count."""
        return len(text.split()) * 1.3
```

## Dynamic Prompt Selection

```python
class DynamicPromptSelector:
    """Select optimal prompt based on context."""

    def __init__(self):
        self.prompts = {
            "simple_query": {
                "template": "Answer briefly: {input}",
                "max_tokens": 100
            },
            "complex_analysis": {
                "template": """Analyze this thoroughly:
{input}

Consider:
1. Key points
2. Implications
3. Recommendations""",
                "max_tokens": 500
            },
            "creative_task": {
                "template": """Be creative with this:
{input}

Feel free to be imaginative while staying helpful.""",
                "max_tokens": 300
            }
        }

    def select(self, task: str, complexity: str = "auto") -> dict:
        """Select appropriate prompt template."""
        if complexity == "auto":
            complexity = self._analyze_complexity(task)

        if complexity == "low":
            return self.prompts["simple_query"]
        elif complexity == "high":
            return self.prompts["complex_analysis"]
        else:
            return self.prompts["creative_task"]

    def _analyze_complexity(self, task: str) -> str:
        """Analyze task complexity."""
        complex_keywords = ["analyze", "compare", "evaluate", "design"]
        if any(kw in task.lower() for kw in complex_keywords):
            return "high"

        simple_keywords = ["what", "when", "where", "how much"]
        if any(kw in task.lower() for kw in simple_keywords):
            return "low"

        return "medium"
```

## Retry with Reflection

```python
class ReflectiveRetry:
    """Retry failed generations with reflection."""

    async def generate_with_retry(
        self,
        llm,
        prompt: str,
        validator,
        max_retries: int = 3
    ) -> str:
        """Generate with validation and reflective retry."""

        for attempt in range(max_retries):
            response = await llm.generate(prompt)

            # Validate
            validation = validator.validate(response)
            if validation["valid"]:
                return response

            # Build reflection prompt
            prompt = f"""Your previous response had an issue: {validation["error"]}

Previous response: {response}

Please try again, addressing this issue:
{prompt}"""

            logger.info("reflective_retry",
                       attempt=attempt,
                       error=validation["error"])

        raise GenerationError(f"Failed after {max_retries} attempts")
```
