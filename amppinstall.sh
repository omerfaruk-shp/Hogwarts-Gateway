# sesoda_final.py
# Mikrofon → intent → Wi-Fi röle (r2ac/r2kap)
# "env" istemiyorsun, anahtarı direkt koda yazdım (istersen boş bırakıp sadece yerel intentle de çalışır).

import re
import time
import tempfile
import requests
import speech_recognition as sr

# ---- AYARLAR ----
HOST = "http://192.168.111.17"
ON_URL  = f"{HOST}/r2ac"
OFF_URL = f"{HOST}/r2kap"

USE_GROQ = True   # Yerel anahtar kelimeye ek olarak Groq'la niyeti netleştirsin mi?
GROQ_API_KEY = "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"  # Groq kullanmayacaksan boş bırak: "" (veya USE_GROQ=False)

# ---- PRATIK HTTP ----
def relay_on():
    try:
        r = requests.get(ON_URL, timeout=3)
        print(f"✅ AÇ ({r.status_code})")
    except Exception as e:
        print(f"❌ AÇ hatası:", e)

def relay_off():
    try:
        r = requests.get(OFF_URL, timeout=3)
        print(f"✅ KAPAT ({r.status_code})")
    except Exception as e:
        print(f"❌ KAPAT hatası:", e)

# ---- YEREL (LLM'SİZ) INTENT ----
# Basit ve hızlı: önce bunu dener, anlaşılmazsa (ve USE_GROQ=True ise) Groq'a sorar.
def local_intent(text: str) -> str:
    if not text:
        return "NONE"
    t = text.lower()
    # "aç" varyantları
    if re.search(r"\b(aç|yak|yak\s*ışığı|ışığı\s*aç|lambayı\s*aç)\b", t):
        return "TURN_ON"
    # "kapat" varyantları
    if re.search(r"\b(kapat|söndür|ışığı\s*kapat|lambayı\s*kapat)\b", t):
        return "TURN_OFF"
    # durum vs.
    if re.search(r"\b(durum|açık mı|kapalı mı|ne halde)\b", t):
        return "STATUS"
    return "NONE"

# ---- (İSTEĞE BAĞLI) GROQ İLE INTENT ----
def groq_intent(text: str) -> str:
    if not USE_GROQ or not GROQ_API_KEY:
        return "NONE"
    try:
        from groq import Groq
        import json
        client = Groq(api_key=GROQ_API_KEY)
        system_prompt = (
            "Sadece GEÇERLİ JSON üret. Açıklama yazma.\n"
            "Şema:\n"
            "{\n"
            '  "intent": "TURN_ON" | "TURN_OFF" | "STATUS" | "NONE"\n'
            "}\n"
            "Örnek eşleşme:\n"
            "- aç, yak → TURN_ON\n"
            "- kapat, söndür → TURN_OFF\n"
            "- durum, açık mı → STATUS\n"
            "Belirsizse NONE. ÇIKTI: Tek satır JSON."
        )
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            response_format={"type": "json_object"},  # json_schema DESTEKLEMİYOR; json_object kullan
            temperature=0.0,
            max_tokens=64,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Komut: {text}"},
            ],
        )
        raw = resp.choices[0].message.content.strip()
        data = json.loads(raw)
        intent = data.get("intent", "NONE")
        if intent not in ("TURN_ON", "TURN_OFF", "STATUS", "NONE"):
            intent = "NONE"
        return intent
    except Exception as e:
        print("ℹ️ Groq intent atlanıyor:", e)
        return "NONE"

# ---- MIKROFON ASR ----
def listen_once(timeout_sec=5, phrase_sec=8) -> str:
    r = sr.Recognizer()
    r.energy_threshold = 350
    r.dynamic_energy_threshold = True
    with sr.Microphone() as source:
        print("🎤 Konuş (örn: 'ışığı aç', 'lambayı kapat')...")
        try:
            audio = r.listen(source, timeout=timeout_sec, phrase_time_limit=phrase_sec)
        except sr.WaitTimeoutError:
            return ""
    # SpeechRecognition ile Google Web Speech kullanmadan direkt metin çevirmeyeceğiz;
    # WAV alıp Groq ASR kullanmak istersen burayı genişletebilirsin.
    # Şimdilik hızlı test için SR'nin offline olmaması nedeniyle basit bir alternatif:
    # Eğer SpeechRecognition'ın 'recognize_google'ı engelliyse, yazı girişi fallback yapılır.
    try:
        text = r.recognize_google(audio, language="tr-TR")
        return text
    except Exception:
        return ""

def main():
    print("Yerel Wi-Fi röle kontrolü (r2). Çıkış: Ctrl+C")
    while True:
        text = listen_once()
        if not text:
            # Ses algılanmadıysa hızlı yazı fallback
            typed = input("Yaz (örn: 'ışığı aç' / Enter=yeniden dinle): ").strip()
            if not typed:
                continue
            text = typed

        print("🗣️ Komut:", text)

        # 1) Yerel intent
        intent = local_intent(text)

        # 2) Belirsizse Groq ile teyit (opsiyonel)
        if intent == "NONE":
            intent = groq_intent(text)

        print("🧭 Intent:", intent)

        if intent == "TURN_ON":
            relay_on()
        elif intent == "TURN_OFF":
            relay_off()
        elif intent == "STATUS":
            print("ℹ️ Ayrı durum endpoint'in yok; sadece AÇ/KAPAT yapıyorum.")
        else:
            print("🤔 Anlaşılmadı. 'ışığı aç' / 'lambayı kapat' gibi söyle/yaz.")

        time.sleep(0.3)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGörüşürüz 👋")
