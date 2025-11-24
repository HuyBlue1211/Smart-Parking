#include <SPI.h>
#include <MFRC522.h>

// ================== Wi-Fi + Firebase (Firestore) ==================
#include <WiFi.h>
#include <Firebase_ESP_Client.h>
#include <time.h>

// Debug trạng thái token Firebase (log ra Serial)
#include <addons/TokenHelper.h>

// ---- điền thông tin của bạn ----
#define WIFI_SSID "TP-Link_15A0"
#define WIFI_PASS "12206476"

#define API_KEY           "AIzaSyChZ_LHuzdEo6boWWP117MlO64D1dRjciI"  // Web API key
#define USER_EMAIL        "esp32@gmail.com"                           // Auth → Users
#define USER_PASSWORD     "123456"
#define FIREBASE_PROJECT_ID "smart-parking-7d341"                     // Project ID
#define FIREBASE_DATABASE_ID "(default)"
// --------------------------------

FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;

static inline String rfc3339Now() {
  time_t now; time(&now);
  struct tm t; gmtime_r(&now, &t);
  char buf[32]; strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &t);
  return String(buf);
}

void wifiInit() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(300);
  }
}

void ntpInit() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov"); // UTC
  time_t now = 0; int tries = 0;
  while (now < 8 * 3600 && tries++ < 20) { delay(500); time(&now); }
  Serial.print("DBG|NTP|epoch="); Serial.println((unsigned long)now);  // > 28800 tức đã sync
}

void firebaseInit() {
  config.api_key = API_KEY;
  auth.user.email = USER_EMAIL;
  auth.user.password = USER_PASSWORD;
  config.max_token_generation_retry = 5;
  config.token_status_callback = tokenStatusCallback; // từ TokenHelper.h
  Firebase.reconnectWiFi(true);
  Firebase.begin(&config, &auth);
}

static inline bool wifiReady() { return WiFi.status() == WL_CONNECTED; }

// ===== Serial (USB) tới Pi =====
#define PC   Serial     // USB CDC
const uint32_t BAUD = 115200;

// ===== RC522 (SPI) — ESP OUT =====
const uint8_t PIN_SCK  = 18;
const uint8_t PIN_MISO = 19;
const uint8_t PIN_MOSI = 23;
const uint8_t PIN_SS   = 5;
const uint8_t PIN_RST  = 22;

MFRC522 r(PIN_SS, PIN_RST);
MFRC522::MIFARE_Key keyA, keyB;

// ===== Buzzer — chỉ beep KHI ĐỌC THÀNH CÔNG =====
const int BUZZ_PIN = 4;
static inline void beep(uint16_t ms = 70) {
  pinMode(BUZZ_PIN, OUTPUT);
  digitalWrite(BUZZ_PIN, HIGH);
  delay(ms);
  digitalWrite(BUZZ_PIN, LOW);
}
static inline void beeps_ok() { beep(60); delay(80); beep(60); }

// ===== Helpers =====
static inline void out(const String &s){ PC.print(s); }
static inline void outln(const String &s){ PC.println(s); }

String uidToHex(const MFRC522::Uid &uid){
  char buf[3*10]{0}; String s;
  for (byte i=0;i<uid.size;i++){ sprintf(buf,"%02X", uid.uidByte[i]); s += buf; }
  return s;
}

// Robust select/auth (giảm timeout)
bool strongSelectCard(uint8_t tries = 6){
  byte atqa[2]; byte atqaSize;
  for (uint8_t i=0;i<tries;i++){
    if (r.PICC_IsNewCardPresent() && r.PICC_ReadCardSerial()) return true;
    if (r.PICC_ReadCardSerial()) return true;
    atqaSize = sizeof(atqa);
    r.PICC_WakeupA(atqa, &atqaSize);
    r.PICC_HaltA(); r.PCD_StopCrypto1();
    delay(15);
  }
  return false;
}

bool robustAuthBlock(byte block, char &keyUsed, uint8_t attempts = 5){
  for (uint8_t t=0; t<attempts; t++){
    MFRC522::StatusCode st = r.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &keyA, &r.uid);
    if (st == MFRC522::STATUS_OK){ keyUsed='A'; return true; }
    st = r.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, &keyB, &r.uid);
    if (st == MFRC522::STATUS_OK){ keyUsed='B'; return true; }
    r.PCD_StopCrypto1();
    r.PCD_Reset(); r.PCD_Init(); r.PCD_AntennaOn(); delay(5);
    if (!strongSelectCard(2)) { delay(10); }
  }
  keyUsed='-';
  return false;
}

MFRC522::StatusCode readBlockD(byte block, byte outb[18], byte &outSize){
  outSize = 18;
  return r.MIFARE_Read(block, outb, &outSize);
}

bool writeZeros16(byte block){
  char k='-';
  if (!robustAuthBlock(block, k, 6)) return false;
  byte zeros[16]; memset(zeros, 0x00, 16);
  MFRC522::StatusCode st = r.MIFARE_Write(block, zeros, 16);
  r.PCD_StopCrypto1();
  return (st == MFRC522::STATUS_OK);
}

// Đọc chuỗi ASCII (trim 0x00) từ mảng 16 byte
String takeAscii(const byte *buf, int maxLen){
  String s = "";
  for (int i=0; i<maxLen; ++i){
    byte c = buf[i];
    if (c == 0) break;
    if (c >= 32 && c <= 126) s += char(c);
  }
  return s;
}

// Giải nén dữ liệu sector 1 (block 4..6) — plate tối đa 16 ký tự; t14 = 14 ký tự
bool unpackDataFromSector1(String &plate, String &t14) {
  char k='-';
  byte rb[18]; byte sz;

  plate = ""; t14 = "";

  // B4 -> plate
  if (!robustAuthBlock(4, k, 6)) return false;
  sz = 18;
  if (readBlockD(4, rb, sz) != MFRC522::STATUS_OK){ r.PCD_StopCrypto1(); return false; }
  r.PCD_StopCrypto1();
  plate = takeAscii(rb, 16);

  // B5 -> t14
  if (!robustAuthBlock(5, k, 6)) return false;
  sz = 18;
  if (readBlockD(5, rb, sz) != MFRC522::STATUS_OK){ r.PCD_StopCrypto1(); return false; }
  r.PCD_StopCrypto1();
  {
    String raw = takeAscii(rb, 16);
    String onlyDigits = "";
    for (int i=0;i<(int)raw.length();++i){
      if (raw[i] >= '0' && raw[i] <= '9') onlyDigits += raw[i];
    }
    if (onlyDigits.length() >= 14) t14 = onlyDigits.substring(0,14);
  }

  // B6 optional
  if (robustAuthBlock(6, k, 4)){
    sz = 18; readBlockD(6, rb, sz); r.PCD_StopCrypto1();
  }

  return (plate.length() > 0 && t14.length() == 14);
}

// ================== Firestore (FS|OUT) ==================
bool fsCloseOutDoc(const String& uid, const String& _docPath,
                   const String& gate_out, long seconds, long fee)
{
  if (!wifiReady()) {
    out("FS_ERR|OUT|"); out(uid); outln("|NO_WIFI");
    return false;
  }

  String docPath = _docPath; docPath.trim();
  if (docPath.length() == 0) {
    out("FS_ERR|OUT|"); out(uid); outln("|EMPTY_PATH");
    return false;
  }

  // Body Firestore patch
  String body = "{ \"fields\": {"
    "\"gate_out\":{\"stringValue\":\""+gate_out+"\"},"
    "\"time_out\":{\"timestampValue\":\""+rfc3339Now()+"\"},"
    "\"seconds\":{\"integerValue\":\""+String(seconds)+"\"},"
    "\"fee\":{\"integerValue\":\""+String(fee)+"\"},"
    "\"currency\":{\"stringValue\":\"VND\"},"
    "\"status\":{\"stringValue\":\"closed\"}"
  "} }";

  // Update mask (chỉ cập nhật các field trên)
  String mask = "gate_out,time_out,seconds,fee,currency,status";

  bool ok = Firebase.Firestore.patchDocument(&fbdo,
                  FIREBASE_PROJECT_ID,
                  FIREBASE_DATABASE_ID,
                  docPath.c_str(),
                  body.c_str(),
                  mask.c_str());

  if (ok) {
    out("FS_OK|OUT|"); outln(uid);
    return true;
  } else {
    out("FS_ERR|OUT|"); out(uid); out("|"); outln(fbdo.errorReason());
    return false;
  }
}

// ===== Nhận lệnh từ Pi (WHO?, BEEP|2, CLR|..., FS|OUT|...) =====
String inbuf;

bool parseClrCmd(const String &line, String &uidOut){
  // Hỗ trợ: "CLR|OUT|<uid>" hoặc "CLR|<uid>"
  uidOut = "";
  if (!line.startsWith("CLR|")) return false;
  int p1 = line.indexOf('|', 4);
  if (p1 < 0){
    uidOut = line.substring(4);
    uidOut.trim();
    return uidOut.length() > 0;
  }
  String mid = line.substring(4, p1);
  if (mid.equalsIgnoreCase("OUT")){
    uidOut = line.substring(p1+1);
    uidOut.trim();
    return uidOut.length() > 0;
  }
  uidOut = mid; uidOut.trim();
  return uidOut.length() > 0;
}

bool sameUidHex(const MFRC522::Uid &u, const String &hex){
  String cur = uidToHex(u);
  return cur.equalsIgnoreCase(hex);
}

void doClearByUid(const String &uidReq){
  if (!strongSelectCard(6)){
    out("ERR|CLR|NO_CARD|"); outln(uidReq);
    return;
  }
  String uidNow = uidToHex(r.uid);
  if (!uidNow.equalsIgnoreCase(uidReq)){
    out("ERR|CLR|UID_MISMATCH|"); out(uidReq); out("|SEEN|"); outln(uidNow);
    r.PICC_HaltA(); r.PCD_StopCrypto1();
    return;
  }

  MFRC522::PICC_Type typ = r.PICC_GetType(r.uid.sak);
  if (!(typ==MFRC522::PICC_TYPE_MIFARE_MINI ||
        typ==MFRC522::PICC_TYPE_MIFARE_1K  ||
        typ==MFRC522::PICC_TYPE_MIFARE_4K)) {
    out("ERR|CLR|TYPE|"); outln(uidReq);
    r.PICC_HaltA(); r.PCD_StopCrypto1();
    return;
  }

  bool ok4 = writeZeros16(4);
  bool ok5 = writeZeros16(5);
  // bool ok6 = writeZeros16(6); // nếu muốn xóa luôn block 6

  r.PICC_HaltA(); r.PCD_StopCrypto1();

  if (ok4 && ok5){
    out("CLR_OK|OUT|"); outln(uidReq);
  } else {
    out("ERR|CLR|WRITE|"); out(uidReq);
    out("|B4="); out(ok4 ? "OK" : "NG");
    out("|B5="); outln(ok5 ? "OK" : "NG");
  }
}

void handle_cmd(const String &line){
  if (line == "WHO?" || line == "WHO" || line == "PING"){
    outln("HELLO|OUT");
    return;
  }
  if (line.startsWith("BEEP|2")){
    beeps_ok();
    return;
  }
  if (line.startsWith("CLR|")){
    String uidReq;
    if (!parseClrCmd(line, uidReq)){
      outln("ERR|CLR|BAD_CMD");
      return;
    }
    doClearByUid(uidReq);
    return;
  }
  if (line.startsWith("FS|OUT|")) {
    // FS|OUT|<uid>|<docPath>|<gate>|<seconds>|<fee>
    int p2 = line.indexOf('|', 7);  if (p2<0) return;
    int p3 = line.indexOf('|', p2+1); if (p3<0) return;
    int p4 = line.indexOf('|', p3+1); if (p4<0) return;
    int p5 = line.indexOf('|', p4+1); if (p5<0) return;
    int p6 = line.indexOf('|', p5+1); // có thể -1 nếu hết chuỗi

    String uid     = line.substring(7,  p2);
    String docPath = line.substring(p2+1, p3); docPath.trim();
    String gate    = line.substring(p3+1, p4);
    String secondsS= line.substring(p4+1, p5);
    String feeS    = (p6<0) ? line.substring(p5+1) : line.substring(p5+1, p6);
    long seconds   = secondsS.toInt();
    long fee       = feeS.toInt();

    fsCloseOutDoc(uid, docPath, gate, seconds, fee);
    return;
  }
  // ignore các lệnh khác
}

// ===== Main =====
String lastUid = "";
unsigned long lastMillis = 0;
const unsigned long COOL_MS = 900;

void setup(){
  PC.begin(BAUD); delay(200);

  // Wi-Fi + Firebase + NTP
  wifiInit();
  ntpInit();
  firebaseInit();

  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI);
  r.PCD_Init(); r.PCD_AntennaOn();
  pinMode(BUZZ_PIN, OUTPUT); digitalWrite(BUZZ_PIN, LOW);

  for (byte i=0;i<6;i++){ keyA.keyByte[i] = 0xFF; keyB.keyByte[i] = 0xFF; }

  // Tăng dung lượng buffer đọc response Firestore (payload dài)
  fbdo.setResponseSize(8192);

  outln("HELLO|OUT");
  outln("DBG|BOOT|ESP32 RC522 Reader/OUT + Firestore");
  outln("DBG|PINS|SS=5,RST=22,SCK=18,MISO=19,MOSI=23,BUZZ=4");
  outln("DBG|BAUD|115200");
}

void loop(){
  // Nhận lệnh từ Pi
  while (PC.available()){
    char c = PC.read();
    if (c=='\n' || c=='\r'){
      if (inbuf.length()){ handle_cmd(inbuf); inbuf=""; }
    } else {
      inbuf += c;
      if (inbuf.length() > 200) inbuf = "";
    }
  }

  // Quét thẻ (giữ nguyên logic cũ)
  if (r.PICC_IsNewCardPresent() && r.PICC_ReadCardSerial()){
    String uid = uidToHex(r.uid);
    unsigned long now = millis();
    if (!(uid == lastUid && (now - lastMillis) < COOL_MS)){
      MFRC522::PICC_Type typ = r.PICC_GetType(r.uid.sak);

      if (typ==MFRC522::PICC_TYPE_MIFARE_MINI ||
          typ==MFRC522::PICC_TYPE_MIFARE_1K  ||
          typ==MFRC522::PICC_TYPE_MIFARE_4K) {

        String plate, t14;
        if (unpackDataFromSector1(plate, t14)){
          out("RD_OK|OUT|"); out(uid); out("|"); out(plate); out("|"); outln(t14);
          beeps_ok();
        } else {
          out("ERR|RD|PARSE|"); outln(uid);
        }
      } else {
        out("ERR|RD|TYPE|"); outln(uid);
      }

      lastUid = uid; lastMillis = now;
    }

    r.PICC_HaltA(); r.PCD_StopCrypto1();
  }
}
