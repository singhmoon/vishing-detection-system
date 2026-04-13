import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

KEYWORDS = {
    "otp": 20,
    "account": 10,
    "bank": 15,
    "urgent": 15,
    "password": 20,
    "verify": 10,
    "suspend": 15,
    "click": 10,
    "link": 10,
    "update": 10,
    "kyc": 15,
    "atm": 10,
    "pin": 20,
    "refund": 10,
    "reward": 10,
}

PHRASES = {
    "share your otp": 30,
    "verify your account": 25,
    "bank account blocked": 25,
    "click the link": 25,
    "update your kyc": 20,
    "atm card blocked": 20,
    "send your pin": 30,
}


def transcribe_audio(file_path: str) -> str:
    import speech_recognition as sr

    recognizer = sr.Recognizer()
    with sr.AudioFile(file_path) as source:
        audio_data = recognizer.record(source)

    try:
        return recognizer.recognize_google(audio_data)
    except Exception:
        return ""


def analyze_audio(file_path: str) -> tuple[float, float, float]:
    import librosa
    import numpy as np

    audio, sr = librosa.load(file_path, sr=16000)
    energy = float(np.mean(audio**2))

    pitch, _ = librosa.piptrack(y=audio, sr=sr)
    pitch_vals = pitch[pitch > 0]
    pitch_vals = pitch_vals[pitch_vals < 500]
    avg_pitch = float(pitch_vals.mean()) if len(pitch_vals) > 0 else 0.0

    duration = float(librosa.get_duration(y=audio, sr=sr))
    return energy, avg_pitch, duration


def analyze_text(text: str) -> tuple[int, list[str], float]:
    from textblob import TextBlob

    text_lower = text.lower()
    score = 0
    matched = []

    for word, weight in KEYWORDS.items():
        if word in text_lower:
            score += weight
            matched.append(word)

    for phrase, weight in PHRASES.items():
        if phrase in text_lower:
            score += weight
            matched.append(phrase)

    sentiment = TextBlob(text).sentiment.polarity if text else 0.0
    return score, matched, sentiment


def build_decision(
    text_score: int,
    sentiment: float,
    energy: float,
    avg_pitch: float,
    speech_rate: float,
) -> tuple[int, list[str], str]:
    risk_score = text_score
    reasons = []

    if text_score >= 30:
        reasons.append("Suspicious banking or urgency keywords detected")

    if sentiment < -0.2:
        risk_score += 10
        reasons.append("Negative tone detected")

    if energy > 0.01:
        risk_score += 10
        reasons.append("High audio energy")

    if avg_pitch > 210:
        risk_score += 10
        reasons.append("High pitch pattern")

    if speech_rate > 2.8:
        risk_score += 10
        reasons.append("Fast speaking rate")

    if risk_score >= 50:
        label = "Scam Call"
    elif risk_score >= 25:
        label = "Suspicious Call"
    else:
        label = "Safe Call"

    return risk_score, reasons, label


class DetectorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Voice Phishing Detection System")
        self.root.geometry("760x640")
        self.root.minsize(700, 560)

        self.file_path = ""
        self.status_var = tk.StringVar(value="Choose a WAV file to begin.")

        self.build_ui()

    def build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=16)
        container.pack(fill="both", expand=True)

        ttk.Label(
            container,
            text="Voice Phishing Detection System",
            font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            container,
            text="Rule-based detector for suspicious voice calls.",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 16))

        controls = ttk.Frame(container)
        controls.pack(fill="x", pady=(0, 12))

        ttk.Button(controls, text="Choose WAV File", command=self.choose_file).pack(side="left")
        ttk.Button(controls, text="Analyze", command=self.start_analysis).pack(side="left", padx=(8, 0))

        self.file_label = ttk.Label(
            container,
            text="No file selected",
            foreground="#444444",
            font=("Segoe UI", 10),
        )
        self.file_label.pack(anchor="w", pady=(0, 10))

        self.status_label = ttk.Label(
            container,
            textvariable=self.status_var,
            foreground="#0a5",
            font=("Segoe UI", 10, "bold"),
        )
        self.status_label.pack(anchor="w", pady=(0, 12))

        self.result_box = tk.Text(
            container,
            wrap="word",
            font=("Consolas", 11),
            height=26,
        )
        self.result_box.pack(fill="both", expand=True)
        self.result_box.insert("1.0", "Results will appear here.\n")
        self.result_box.config(state="disabled")

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select WAV file",
            filetypes=[("WAV files", "*.wav")],
        )
        if path:
            self.file_path = path
            self.file_label.config(text=path)
            self.status_var.set("File selected. Ready to analyze.")

    def start_analysis(self) -> None:
        if not self.file_path:
            messagebox.showwarning("No file", "Please choose a WAV file first.")
            return

        self.status_var.set("Analyzing audio. Please wait...")
        self.set_result_text("Running analysis...\n")

        worker = threading.Thread(target=self.run_analysis, daemon=True)
        worker.start()

    def run_analysis(self) -> None:
        try:
            energy, avg_pitch, duration = analyze_audio(self.file_path)
            text = transcribe_audio(self.file_path)
            text_score, matched_words, sentiment = analyze_text(text)
            speech_rate = len(text.split()) / duration if duration > 0 else 0.0
            risk_score, reasons, label = build_decision(
                text_score,
                sentiment,
                energy,
                avg_pitch,
                speech_rate,
            )

            report = [
                f"Selected File: {self.file_path}",
                "",
                "Recognized Text:",
                text if text else "No speech detected",
                "",
                f"Keyword Score: {text_score}",
                f"Matched Signals: {', '.join(matched_words) if matched_words else 'None'}",
                f"Sentiment: {sentiment:.3f}",
                f"Energy: {energy:.6f}",
                f"Pitch: {avg_pitch:.2f}",
                f"Speech Rate: {speech_rate:.2f}",
                f"Risk Score: {risk_score}",
                f"Reasons: {', '.join(reasons) if reasons else 'No strong scam indicators found'}",
                "",
                f"Final Decision: {label}",
            ]
            self.root.after(0, lambda: self.finish_analysis("\n".join(report), label))
        except Exception as exc:
            self.root.after(0, lambda: self.fail_analysis(str(exc)))

    def finish_analysis(self, report: str, label: str) -> None:
        self.set_result_text(report)
        self.status_var.set(f"Analysis complete: {label}")

    def fail_analysis(self, error_text: str) -> None:
        self.set_result_text(f"Unable to process the audio file.\n\nError: {error_text}")
        self.status_var.set("Analysis failed.")

    def set_result_text(self, text: str) -> None:
        self.result_box.config(state="normal")
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", text)
        self.result_box.config(state="disabled")


def main() -> None:
    root = tk.Tk()
    style = ttk.Style()
    if "vista" in style.theme_names():
        style.theme_use("vista")
    DetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
