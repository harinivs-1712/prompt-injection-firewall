"""Batch wrapper around the Hugging Face PIGuard classifier."""
from __future__ import annotations

from typing import Any, Sequence

MODEL_NAME = "leolee99/PIGuard"
BATCH_SIZE = 8


class PIGuardScorer:
    """Load PIGuard once and score text batches, retaining truncation metadata."""

    def __init__(self, batch_size: int = BATCH_SIZE) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
        except ImportError as exc:
            raise RuntimeError(
                "PIGuard dependencies are missing. Install requirements.txt first."
            ) from exc

        self.batch_size = batch_size
        self.device = 0 if torch.cuda.is_available() else -1
        # Load the model-card tokenizer/classifier explicitly from the local
        # cache, then wrap them in the recommended text-classification pipeline.
        # This avoids unnecessary Hub metadata calls during offline evaluation.
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, local_files_only=True)
            model = AutoModelForSequenceClassification.from_pretrained(
                MODEL_NAME, trust_remote_code=True, local_files_only=True,
            )
        except (OSError, ValueError):
            # First run: download the tokenizer and model; later runs prefer
            # the local cache and avoid hub metadata requests.
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
            model = AutoModelForSequenceClassification.from_pretrained(
                MODEL_NAME, trust_remote_code=True,
            )
        self.classifier = pipeline(
            "text-classification", model=model, tokenizer=self.tokenizer,
            truncation=True, device=self.device,
        )
        model = self.classifier.model
        id2label = getattr(model.config, "id2label", {})
        self.injection_labels = {
            str(label).lower() for label in id2label.values()
            if "injection" in str(label).lower()
        }
        if not self.injection_labels:
            raise ValueError(f"No injection class found in PIGuard id2label: {id2label!r}")
        config_limit = getattr(model.config, "max_position_embeddings", None)
        tokenizer_limit = getattr(self.tokenizer, "model_max_length", None)
        limits = [n for n in (config_limit, tokenizer_limit) if isinstance(n, int) and 0 < n < 1_000_000]
        if not limits:
            raise ValueError("Could not determine PIGuard's maximum token length")
        self.max_length = min(limits)

    def _is_truncated(self, text: str) -> bool:
        token_ids = self.tokenizer(text, add_special_tokens=True, truncation=False)["input_ids"]
        return len(token_ids) > self.max_length

    def score(self, texts: Sequence[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any] | None] = [None] * len(texts)
        for start in range(0, len(texts), self.batch_size):
            batch = list(texts[start:start + self.batch_size])
            raw = self.classifier(batch, top_k=None, truncation=True, batch_size=self.batch_size)
            # Transformers returns list[list[dict]] for a batch with top_k=None.
            if len(batch) == 1 and raw and isinstance(raw[0], dict):
                raw = [raw]
            if len(raw) != len(batch):
                raise RuntimeError("PIGuard returned a different number of results than inputs")
            for offset, class_scores in enumerate(raw):
                if isinstance(class_scores, dict):
                    class_scores = [class_scores]
                matches = [item for item in class_scores if str(item.get("label", "")).lower() in self.injection_labels]
                if not matches:
                    raise ValueError(f"PIGuard output has no injection label: {class_scores!r}")
                top = max(class_scores, key=lambda item: float(item["score"]))
                results[start + offset] = {
                    "piguard_label": str(top["label"]),
                    "piguard_injection_score": float(max(float(x["score"]) for x in matches)),
                    "truncated": self._is_truncated(batch[offset]),
                }
        return [r for r in results if r is not None]
