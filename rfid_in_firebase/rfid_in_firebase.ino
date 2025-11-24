#include <SPI.h>
#include <MFRC522.h>

// ================== Wi-Fi + Firebase (Firestore) ==================
#include <WiFi.h>
#include <Firebase_ESP_Client.h>
#include <time.h>

// ---- FILL ME ----
#define WIFI_SSID "TP-Link_15A0"
#define WIFI_PASS "12206476"

#define API_KEY   "AIzaSyChZ_LHuzdEo6boWWP117MlO64D1dRjciI"          // Web API key (app Web → Config)
#define USER_EMAIL "esp32@gmail.com"             // Auth → Users
#define USER_PASSWORD "123456"
#define FIREBASE_PROJECT_ID "smart-parking-7d341"   // Project ID
#define FIREBASE_DATABASE_ID "(default)"                  // để nguyên
// ------------------

FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;

String rfc3339Now() {
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
}

void firebaseInit() {
  config.api_key = API_KEY;
  auth.user.email = USER_EMAIL;
  auth.user.password = USER_PASSWORD;
  Firebase.reconnectWiFi(true);
  Firebase.begin(&config, &auth);
}

// ================== Serial ports ==================
#define PC   Serial      // USB Serial Monitor
#define COM  Serial2     // UART2 -> Pi (GPIO16/17)
const uint32_t BAUD = 115200;
const int RX2_PIN = 16;   // từ Pi TXD0 (GPIO14)
const int TX2_PIN = 17;   // tới Pi RXD0 (GPIO15)

// ================== RC522 (SPI) ==================
const uint8_t PIN_SCK  = 18;
const uint8_t PIN_MISO = 19;
const uint8_t PIN_MOSI = 23;
const uint8_t PIN_SS   = 5;
const uint8_t PIN_RST  = 22;

MFRC522 r(PIN_SS, PIN_RST);
MFRC522::MIFARE_Key keyA, keyB;

// ================== Buzzer ==================
const int BUZZ_PIN = 4;
static inline void beep(uint16_t ms=70){
  pinMode(BUZZ_PIN, OUTPUT);
  digitalWrite(BUZZ_PIN, HIGH);
  delay(ms);
  digitalWrite(BUZZ_PIN, LOW);
}

// ================== Helpers ==================
void outln(const String &s){ COM.println(s); PC.println(s); }
void out(const String &s){ COM.print(s); PC.print(s); }

String uidToHex(const MFRC522::Uid &uid){
  char buf[3*10]{0}; String s;
  for (byte i=0;i<uid.size;i++){ sprintf(buf,"%02X", uid.uidByte[i]); s += buf; }
  return s;
}

// Robust select/auth
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

MFRC522::StatusCode writeBlockD(byte block, const byte* data16){
  return r.MIFARE_Write(block, (byte*)data16, 16);
}
MFRC522::StatusCode readBlockD(byte block, byte out[18], byte &outSize){
  outSize = 18;
  return r.MIFARE_Read(block, out, &outSize);
}

void packData(const String &plate, const String &t14, byte out48[48]){
  memset(out48, 0, 48);
  // PLATE 0..15
  for (int i=0;i<(int)min((size_t)16, plate.length()); ++i) out48[i] = plate[i];
  // T14 16..29 (14 ký tự)
  for (int i=0;i<14 && i<(int)t14.length(); ++i) out48[16+i] = t14[i];
  // Marker tùy chọn 32..35
  out48[32]='P'; out48[33]='1'; out48[34]='A'; out48[35]=0;
}

// ===== Ghi sector1 (block 4-6) =====
volatile bool writeBusy = false;

void doWriteSector1(const String &plate, const String &t14){
  if (writeBusy) { outln("DBG|WR|BUSY"); return; }
  writeBusy = true;

  beep(40);
  out("DBG|WR|PAYLOAD|plate="); out(plate); out("|t14="); outln(t14);

  r.PCD_Reset(); r.PCD_Init(); r.PCD_AntennaOn(); delay(5);
  if (!strongSelectCard(8)){
    outln("ERR|WR_TIMEOUT"); beep(140); writeBusy=false; return;
  }

  MFRC522::PICC_Type typ = r.PICC_GetType(r.uid.sak);
  String uid = uidToHex(r.uid);
  if (!(typ==MFRC522::PICC_TYPE_MIFARE_MINI || typ==MFRC522::PICC_TYPE_MIFARE_1K || typ==MFRC522::PICC_TYPE_MIFARE_4K)){
    out("ERR|WR_TYPE|"); outln(uid); beep(140); writeBusy=false; return;
  }

  byte payload[48]; packData(plate, t14, payload);
  char k='-';

  // B4
  if (!robustAuthBlock(4, k, 6)){ outln("ERR|AUTH|B4"); beep(140); writeBusy=false; return; }
  if (writeBlockD(4, payload+0) != MFRC522::STATUS_OK){ outln("ERR|WRITE|B4"); beep(140); writeBusy=false; return; }
  r.PCD_StopCrypto1(); delay(5);

  // B5
  if (!robustAuthBlock(5, k, 6)){ outln("ERR|AUTH|B5"); beep(140); writeBusy=false; return; }
  if (writeBlockD(5, payload+16) != MFRC522::STATUS_OK){ outln("ERR|WRITE|B5"); beep(140); writeBusy=false; return; }
  r.PCD_StopCrypto1(); delay(5);

  // B6
  if (!robustAuthBlock(6, k, 6)){ outln("ERR|AUTH|B6"); beep(140); writeBusy=false; return; }
  if (writeBlockD(6, payload+32) != MFRC522::STATUS_OK){ outln("ERR|WRITE|B6"); beep(140); writeBusy=false; return; }
  r.PCD_StopCrypto1();

  out("WR_OK|IN|"); outln(uid);
  beep(100);
  writeBusy = false;
}

// ================== Firestore (FS|IN) ==================
bool fsCreateInDoc(const String& uid, const String& plate, const String& gate){
  String body = "{ \"fields\": {"
    "\"plate\":{\"stringValue\":\""+plate+"\"},"
    "\"gate_in\":{\"stringValue\":\""+gate+"\"},"
    "\"time_in\":{\"timestampValue\":\""+rfc3339Now()+"\"},"
    "\"uid\":{\"stringValue\":\""+uid+"\"},"
    "\"status\":{\"stringValue\":\"open\"}"
  "} }";

  if (Firebase.Firestore.createDocument(&fbdo, FIREBASE_PROJECT_ID, FIREBASE_DATABASE_ID,
                                        "parking_sessions", body.c_str())) {
    // Lấy docPath từ payload JSON trả về
    String p = fbdo.payload();
    int i = p.indexOf("/documents/");
    String path = (i>0) ? p.substring(i+11, p.indexOf("\"", i+11)) : "";
    out("FS_OK|IN|"); out(uid); out("|"); outln(path);
    return true;
  } else {
    out("FS_ERR|IN|"); out(uid); out("|"); outln(fbdo.errorReason());
    return false;
  }
}

// ===== Parser lệnh từ Pi =====
String inbuf;
void cmd_parse(const String &line){
  if (line.startsWith("WR|IN|")){
    int p2 = line.indexOf('|', 6);
    if (p2 < 0) { outln("ERR|WR_BAD"); beep(140); return; }
    String plate = line.substring(6, p2);
    String t14   = line.substring(p2+1);
    doWriteSector1(plate, t14);

  } else if (line.startsWith("FS|IN|")) {
      // Định dạng: FS|IN|uid|plate|gate
  int i0 = 6; // sau "FS|IN|"
  int p1 = line.indexOf('|', i0);
  if (p1 < 0) return;

  int p2 = line.indexOf('|', p1 + 1);
  String uid   = line.substring(i0, p1);
  String plate = (p2 > 0) ? line.substring(p1 + 1, p2) : line.substring(p1 + 1);
  String gate  = (p2 > 0) ? line.substring(p2 + 1) : String("");

  uid.trim(); plate.trim(); gate.trim();
  if (uid.length() == 0) { outln("FS_ERR|IN|NO_UID"); return; }

  fsCreateInDoc(uid, plate, gate);

  } else if (line == "PING"){
    outln("PONG");

  } else {
    out("DBG|CMD|UNK|"); outln(line);
  }
}

// ===== Phát hiện thẻ / OFF =====
String lastUid = "";
unsigned long lastSeen = 0;
const unsigned long COOL_MS = 1200;    // chống spam TRIG
const unsigned long OFF_HYST_MS = 120; // trễ nhỏ phát OFF khi mất thẻ

void setup(){
  PC.begin(BAUD); delay(200);
  COM.begin(BAUD, SERIAL_8N1, RX2_PIN, TX2_PIN);

  // Wi-Fi + Firebase + NTP
  wifiInit();
  ntpInit();
  firebaseInit();

  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI);
  r.PCD_Init(); r.PCD_AntennaOn();
  pinMode(BUZZ_PIN, OUTPUT); digitalWrite(BUZZ_PIN, LOW);

  for (byte i=0;i<6;i++){ keyA.keyByte[i] = 0xFF; keyB.keyByte[i] = 0xFF; }

  outln("READY");
  outln("DBG|BOOT|ESP32 RC522 Writer/IN + Firestore");
  outln("DBG|PINS|SS=5,RST=22,SCK=18,MISO=19,MOSI=23,BUZZ=4,UART2 RX=16,TX=17");
  outln("DBG|BAUD|115200");
}

void loop(){
  // Nhận lệnh từ Pi
  while (COM.available()){
    char c = COM.read();
    if (c=='\n' || c=='\r'){
      if (inbuf.length()){ cmd_parse(inbuf); inbuf=""; }
    } else {
      inbuf += c;
      if (inbuf.length() > 240) inbuf = "";
    }
  }

  // Đang ghi -> tạm bỏ qua phát hiện để tránh lẫn
  if (writeBusy) return;

  bool hasCard = false;
  if (r.PICC_IsNewCardPresent() && r.PICC_ReadCardSerial()){
    hasCard = true;
    String uid = uidToHex(r.uid);
    unsigned long now = millis();

    if (!(uid == lastUid && (now - lastSeen) < COOL_MS)){
      out("TRIG|IN|"); outln(uid);
      beep(40);
      lastUid = uid;
    }
    lastSeen = now;

    r.PICC_HaltA(); r.PCD_StopCrypto1();
  }

  // Mất thẻ một lúc -> phát OFF|IN|<uid> để Pi reset trạng thái
  if (!hasCard && lastUid.length()){
    if (millis() - lastSeen > OFF_HYST_MS){
      out("OFF|IN|"); outln(lastUid);
      lastUid = "";
    }
  }
}
