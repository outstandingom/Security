```python
import whisper
import pyttsx3
from lingua import Language, LanguageDetectorBuilder
import pyaudio
import wave
import os
import json
import torch
from transformers import pipeline, SentenceTransformer
from duckduckgo_search import DDGS
import sounddevice as sd
import numpy as np
import openwakeword
from openwakeword.model import Model
import webrtcvad
import faiss
import collections

# ---------- CONFIG ----------
NEO_NAME = "Neo"
MODEL_SIZE = "medium"  # Better accuracy, multilingual support
WAKE_WORD = "hey_jarvis"  # Pre-trained model that auto-downloads
CHUNK = 320  # For VAD, smaller chunk
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 16000
SILENCE_DURATION = 1  # seconds of silence to stop recording
VAD_AGGRESSIVENESS = 3  # 0-3, higher more aggressive
MEMORY_FILE = "neo_memory.json"
DATASET_FILE = "neo_dataset.jsonl"  # For future fine-tuning with rewards
KNOWLEDGE_FILE = "neo_knowledge.json"
EMBEDDING_MODEL = 'all-MiniLM-L6-v2'
LLM_MODEL = "microsoft/phi-3-mini-4k-instruct"
DIMENSION = 384  # For all-MiniLM-L6-v2
TOP_K = 3  # Retrieve top 3 relevant memories
REWARD_THRESHOLD = 0.5  # For filtering low-reward memories in retrieval

# Load or initialize
if os.path.exists(MEMORY_FILE):
    with open(MEMORY_FILE, 'r') as f:
        conversation_history = json.load(f)
else:
    conversation_history = []

if os.path.exists(KNOWLEDGE_FILE):
    with open(KNOWLEDGE_FILE, 'r') as f:
        KNOWLEDGE_BASE = json.load(f)
else:
    KNOWLEDGE_BASE = {}

# For fine-tuning data collection
if not os.path.exists(DATASET_FILE):
    open(DATASET_FILE, 'w').close()

# ---------- LOAD MODELS ----------
print("Loading models, please wait... This may take a few minutes.")
# Whisper for STT (local)
whisper_model = whisper.load_model(MODEL_SIZE)
# pyttsx3 for TTS (offline)
tts_engine = pyttsx3.init()
tts_engine.setProperty('voice', 'english')  # Customize
# Local LLM
llm_pipeline = pipeline("text-generation", model=LLM_MODEL, trust_remote_code=True, device_map="auto", torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32)
# Embedder for semantic memory
embedder = SentenceTransformer(EMBEDDING_MODEL)
# FAISS index
index = faiss.IndexFlatL2(DIMENSION)
texts = []  # Corresponding texts for retrieval
rewards = []  # Corresponding rewards for each memory entry
# Load existing embeddings if any
if os.path.exists("faiss_index.index"):
    index = faiss.read_index("faiss_index.index")
    with open("faiss_texts.json", 'r') as f:
        texts = json.load(f)
    if os.path.exists("faiss_rewards.json"):
        with open("faiss_rewards.json", 'r') as f:
            rewards = json.load(f)
    else:
        rewards = [0] * len(texts)  # Default to 0 if not present
# Language detector (better for mixed)
detector = LanguageDetectorBuilder.from_languages(Language.ENGLISH, Language.HINDI).build()
# Wake word (adjust threshold)
oww_model = Model(wakeword_models=[WAKE_WORD])  # Will auto-download if not present
WAKE_THRESHOLD = 0.7  # Higher to reduce false positives
# VAD
vad = webrtcvad.Vad(VAD_AGGRESSIVENESS)

# ---------- AUDIO INPUT WITH VAD ----------
def record_audio():
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
    print("🎙️ Recording...")
    frames = []
    silence_count = 0
    while True:
        data = stream.read(CHUNK)
        frames.append(data)
        if vad.is_speech(data, RATE):
            silence_count = 0
        else:
            silence_count += 1
        if silence_count > (SILENCE_DURATION * RATE // CHUNK):
            break
    stream.stop_stream()
    stream.close()
    p.terminate()
    return b''.join(frames)

def save_audio_to_wav(audio_data):
    with wave.open("temp_input.wav", 'wb') as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(2)  # Fixed: 16-bit audio = 2 bytes
        wf.setframerate(RATE)
        wf.writeframes(audio_data)

# ---------- SPEECH TO TEXT ----------
def listen():
    try:
        audio_data = record_audio()
        save_audio_to_wav(audio_data)
        result = whisper_model.transcribe("temp_input.wav")
        text = result["text"].strip()
        print("🧑 You:", text)
        return text
    except Exception as e:
        print(f"STT Error: {e}")
        return ""

# ---------- SELF-LEARNING: SEARCH WEB ----------
def research(topic):
    try:
        with DDGS() as ddgs:
            results = [r for r in ddgs.text(topic, max_results=5)]
        summaries = [r['body'] for r in results]
        knowledge = "\n".join(summaries)
        # To improve: Cross-check
        fact_check_query = f"is {topic} accurate site:wikipedia.org"
        check_results = [r['body'] for r in ddgs.text(fact_check_query, max_results=2)]
        knowledge += "\nFact check: " + "\n".join(check_results)
        KNOWLEDGE_BASE[topic] = knowledge
        with open(KNOWLEDGE_FILE, 'w') as f:
            json.dump(KNOWLEDGE_BASE, f)
        return knowledge
    except Exception as e:
        print(f"Research Error: {e}")
        return "No information found."

# ---------- AI THINKING WITH MEMORY AND LEARNING ----------
def think(user_text, lang):
    global conversation_history, index, texts, rewards
    try:
        # Retrieve relevant memories (filter high-reward ones)
        user_emb = embedder.encode([user_text])
        distances, indices = index.search(user_emb, TOP_K * 2)  # Retrieve more to filter
        relevant = []
        for dist, i in zip(distances[0], indices[0]):
            if i < len(texts) and rewards[i] >= REWARD_THRESHOLD:
                relevant.append(texts[i])
            if len(relevant) >= TOP_K:
                break
        history_str = "\n".join(relevant)

        # Build recent conversation history for prompt (last 10 turns for context)
        recent_history = ""
        for msg in conversation_history[-10:]:
            if msg["role"] == "user":
                recent_history += f"User: {msg['content']}\n"
            else:
                recent_history += f"{NEO_NAME}: {msg['content']}\n"

        # Add past learnings or low-reward reflections
        low_reward_reflections = [KNOWLEDGE_BASE[k] for k in KNOWLEDGE_BASE if k.startswith("learning_") and "improve" in KNOWLEDGE_BASE[k].lower()]
        reflection_str = "\n".join(low_reward_reflections[:3])  # Limit to recent 3

        # System prompt with RL elements
        system_prompt = f"You are {NEO_NAME}, a calm, efficient personal AI assistant. Be practical, short, and helpful. Learn from interactions and past feedback. Think step by step before answering. Past improvements: {reflection_str}"

        # Check if needs research
        knowledge = ""
        if "research" in user_text.lower() or "best way" in user_text.lower():
            topic = user_text.split("research")[-1].strip() if "research" in user_text else user_text
            print(f"🤖 {NEO_NAME} researching: {topic}")
            knowledge = research(topic)
            prompt_add = f"\nBased on this knowledge: {knowledge}\nAnalyze and provide best solution."
        else:
            prompt_add = ""

        # Full prompt with recent history and retrieved info
        full_prompt = f"{system_prompt}\nRelevant past info: {history_str}\n{recent_history}\nUser: {user_text}\n{NEO_NAME}:"

        if lang == "hi":
            full_prompt += " Reply ONLY in Hindi."
        else:
            full_prompt += " Reply ONLY in English."

        # Generate response
        response = llm_pipeline(full_prompt, max_new_tokens=200, do_sample=True, temperature=0.7)[0]['generated_text']
        reply = response.split(f"{NEO_NAME}:")[-1].strip()

        # Self-questioning for learning
        self_question = f"How can I improve based on: {user_text}? Think step by step."
        self_answer = llm_pipeline(self_question, max_new_tokens=150)[0]['generated_text']
        print(f"🤖 {NEO_NAME} learning: {self_answer}")
        # Store learning as knowledge
        KNOWLEDGE_BASE["learning_" + str(len(KNOWLEDGE_BASE))] = self_answer

        # Temporarily add to history (reward will be added later)
        conversation_history.append({"role": "user", "content": user_text})
        conversation_history.append({"role": "assistant", "content": reply})

        # Update semantic memory later after reward

        return reply, full_prompt
    except Exception as e:
        print(f"Thinking Error: {e}")
        return "Sorry, I encountered an error.", ""

# ---------- TEXT TO SPEECH ----------
def speak(text):
    try:
        tts_engine.say(text)
        tts_engine.runAndWait()
    except Exception as e:
        print(f"TTS Error: {e}")

# ---------- WAKE WORD DETECTION ----------
def wait_for_wake_word():
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
    print("🎙️ Listening for wake word...")
    buffer = collections.deque(maxlen=10)  # For noise suppression, simple averaging (placeholder)
    while True:
        data = stream.read(CHUNK)
        # Simple noise reduction: average buffer
        buffer.append(np.frombuffer(data, dtype=np.int16))
        avg_data = np.mean(buffer, axis=0).astype(np.int16)
        prediction = oww_model.predict(avg_data.tobytes())  # Ensure bytes input
        if prediction.get(WAKE_WORD, 0) > WAKE_THRESHOLD:
            print("Wake word detected!")
            break
    stream.stop_stream()
    stream.close()
    p.terminate()

# ---------- MAIN LOOP WITH RL ELEMENTS ----------
speak(f"{NEO_NAME} online. Ready.")
while True:
    wait_for_wake_word()
    user_text = listen()
    if not user_text:
        continue
    if "stop" in user_text.lower() or "बंद" in user_text:
        speak(f"{NEO_NAME} shutting down.")
        break
    try:
        detected_lang = detector.detect_language_of(user_text)
        lang = detected_lang.iso_code_639_1.name.lower() if detected_lang else "en"
    except:
        lang = "en"
    reply, full_prompt = think(user_text, lang)
    print(f"🤖 {NEO_NAME}:", reply)
    speak(reply)

    # Task success scoring (user feedback as reward signal)
    speak("Was my response helpful? Please say yes or no.")
    feedback = listen().lower()
    if "yes" in feedback:
        reward = 1
        print("🤖 Reward: 1 (Positive feedback)")
    else:
        reward = 0
        print("🤖 Reward: 0 (Negative feedback)")

    # Add reward to history
    conversation_history[-1]["reward"] = reward
    with open(MEMORY_FILE, 'w') as f:
        json.dump(conversation_history, f)

    # Add to dataset for future fine-tuning (with reward for RLHF-style)
    dataset_entry = {"prompt": full_prompt, "completion": reply, "reward": reward}
    with open(DATASET_FILE, 'a') as f:
        f.write(json.dumps(dataset_entry) + "\n")

    # Online fine-tuning simulation: If low reward, trigger evaluation loop to improve
    if reward == 0:
        print("🤖 Evaluation loop: Generating improved response...")
        improve_prompt = f"Previous response was not helpful. User: {user_text}\nBad response: {reply}\nImprove it step by step."
        improved_reply = llm_pipeline(improve_prompt, max_new_tokens=200, do_sample=True, temperature=0.7)[0]['generated_text'].strip()
        print(f"🤖 Improved {NEO_NAME}:", improved_reply)
        speak(improved_reply)
        # Replace in history
        conversation_history[-1]["content"] = improved_reply
        conversation_history[-1]["reward"] = 0.5  # Partial reward for attempt
        with open(MEMORY_FILE, 'w') as f:
            json.dump(conversation_history, f)
        # Add improved to dataset
        with open(DATASET_FILE, 'a') as f:
            f.write(json.dumps({"prompt": full_prompt, "completion": improved_reply, "reward": 0.5}) + "\n")

    # Add to semantic memory with reward (for RL filtering)
    new_text = f"User: {user_text}\n{NEO_NAME}: {conversation_history[-1]['content']}"
    new_emb = embedder.encode([new_text])
    index.add(new_emb)
    texts.append(new_text)
    rewards.append(conversation_history[-1]["reward"])
    if len(texts) > 1000:  # Simple forgetting, but retain high-reward
        high_reward_indices = [i for i, r in enumerate(rewards) if r >= REWARD_THRESHOLD][-500:]
        texts = [texts[i] for i in high_reward_indices]
        rewards = [rewards[i] for i in high_reward_indices]
        index.reset()
        emb_matrix = embedder.encode(texts)
        index.add(emb_matrix)

    # Save index and rewards
    faiss.write_index(index, "faiss_index.index")
    with open("faiss_texts.json", 'w') as f:
        json.dump(texts, f)
    with open("faiss_rewards.json", 'w') as f:
        json.dump(rewards, f)

# Security: Set permissions
os.chmod(MEMORY_FILE, 0o600)
os.chmod(DATASET_FILE, 0o600)
os.chmod(KNOWLEDGE_FILE, 0o600)
```
