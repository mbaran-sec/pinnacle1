#include <Arduino.h>
#include <Wire.h>
#include <SPI.h>
#include <Preferences.h>
#include <LiquidCrystal_I2C.h>
#include <Keypad.h>
#include <MFRC522.h>
#include <esp_task_wdt.h>
#include <esp_idf_version.h>

// ============================ CONFIGURATION ================================
static const bool DEBUG_ENABLED = true;
static const char ARM_PIN[] = "1234"; // Never logged.
static const byte AUTHORIZED_UID[] = {0x01, 0x02, 0x03, 0x04}; //Change this according to card
static const byte AUTHORIZED_UID_LENGTH = sizeof(AUTHORIZED_UID);
static const uint8_t LCD_I2C_ADDRESS = 0x27;
static const uint8_t LCD_COLUMNS = 16, LCD_ROWS = 2;

// GPIO assignments: no ESP32 boot/strapping or flash pins are used.
static const uint8_t PIN_LCD_SDA = 21, PIN_LCD_SCL = 22;
static const uint8_t PIN_RFID_SCK = 18, PIN_RFID_MISO = 19;
static const uint8_t PIN_RFID_MOSI = 23, PIN_RFID_SS = 27;
static const uint8_t PIN_PIR = 4, PIN_TAMPER = 33;
static const uint8_t PIN_LED_GREEN = 25, PIN_LED_RED = 26, PIN_BUZZER = 32;
static byte keypadColPins[] = {13, 14, 16, 17};
// GPIO 34/35/36/39 are input-only: install external 10k pull-ups to 3.3 V.
static byte keypadRowPins[] = {34, 35, 36, 39};
static char keypadLayout[4][4] = {{'1','2','3','A'}, {'4','5','6','B'},
                                  {'7','8','9','C'}, {'*','0','#','D'}};

// NC contact wired GPIO -> contact -> GND with INPUT_PULLUP.
static const uint8_t TAMPER_CLOSED_LEVEL = LOW;
static const uint32_t TAMPER_DEBOUNCE_MS = 50;
static const uint32_t RFID_HEALTH_CHECK_MS = 5000;
static const uint32_t RFID_AUTH_WINDOW_MS = 30000;
static const uint32_t NOTICE_DURATION_MS = 1500;
static const uint32_t WDT_TIMEOUT_SECONDS = 10;

#define DBG(fmt, ...) do { if (DEBUG_ENABLED) Serial.printf("[IDS] " fmt "\n", ##__VA_ARGS__); } while (0)

enum SecurityState : uint8_t { DISARMED, ARMED, ALARM, TAMPER_ALARM, FAULT };
static bool validState(uint8_t s) { return s <= FAULT; }
static bool secureState(SecurityState s) { return s == ARMED || s == ALARM || s == TAMPER_ALARM; }
static bool activeUntil(uint32_t until, uint32_t now) { return (int32_t)(until - now) > 0; }
static const char *stateName(SecurityState s) {
  switch (s) { case DISARMED:return "DISARMED"; case ARMED:return "ARMED";
    case ALARM:return "ALARM"; case TAMPER_ALARM:return "TAMPER_ALARM";
    case FAULT:return "FAULT"; default:return "INVALID"; }
}

class Storage {
  Preferences p;
 public:
  void begin() { p.begin("intrusion", false); }
  void save(SecurityState s, SecurityState resume) {
    p.putUChar("state", (uint8_t)s); p.putUChar("resume", (uint8_t)resume);
  }
  SecurityState state() {
    uint8_t s = p.getUChar("state", DISARMED);
    return validState(s) ? (SecurityState)s : DISARMED;
  }
  SecurityState resume() {
    uint8_t s = p.getUChar("resume", ARMED);
    return validState(s) && secureState((SecurityState)s) ? (SecurityState)s : ARMED;
  }
};

class Display {
  LiquidCrystal_I2C lcd;
  bool available = false;
  char old[2][17] = {{0}, {0}};
  void line(uint8_t row, const char *s) {
    char out[17]; memset(out, ' ', 16); out[16] = 0;
    for (uint8_t i=0; s && s[i] && i<16; ++i) out[i] = s[i];
    if (!strcmp(out, old[row])) return;
    lcd.setCursor(0, row); lcd.print(out); strncpy(old[row], out, 17);
  }
 public:
  Display(): lcd(LCD_I2C_ADDRESS, LCD_COLUMNS, LCD_ROWS) {}
  bool begin() {
    Wire.begin(PIN_LCD_SDA, PIN_LCD_SCL);
    Wire.beginTransmission(LCD_I2C_ADDRESS);
    if (Wire.endTransmission() != 0) return false;
    lcd.init(); lcd.backlight(); available = true; show("INITIALIZING...", ""); return true;
  }
  void show(const char *a, const char *b) { if (available) { line(0,a); line(1,b); } }
};

class Tamper {
  uint8_t stable = HIGH, candidate = HIGH;
  uint32_t changed = 0;
 public:
  void begin() { pinMode(PIN_TAMPER, INPUT_PULLUP); stable = candidate = digitalRead(PIN_TAMPER); changed = millis(); }
  void update(uint32_t now) {
    uint8_t raw = digitalRead(PIN_TAMPER);
    if (raw != candidate) { candidate = raw; changed = now; }
    if (candidate != stable && now - changed >= TAMPER_DEBOUNCE_MS) stable = candidate;
  }
  bool closed() const { return stable == TAMPER_CLOSED_LEVEL; }
};

class Rfid {
  MFRC522 reader;
 public:
  Rfid(): reader(PIN_RFID_SS, MFRC522::UNUSED_PIN) {}
  bool begin() { SPI.begin(PIN_RFID_SCK, PIN_RFID_MISO, PIN_RFID_MOSI, PIN_RFID_SS); reader.PCD_Init(); return healthy(); }
  bool healthy() { byte version=reader.PCD_ReadRegister(MFRC522::VersionReg); return version != 0x00 && version != 0xFF; }
  bool authorized() {
    if (!reader.PICC_IsNewCardPresent() || !reader.PICC_ReadCardSerial()) return false;
    bool ok = reader.uid.size == AUTHORIZED_UID_LENGTH;
    for (byte i=0; ok && i<AUTHORIZED_UID_LENGTH; ++i) ok = reader.uid.uidByte[i] == AUTHORIZED_UID[i];
    reader.PICC_HaltA(); reader.PCD_StopCrypto1();
    DBG("RFID %s", ok ? "authorized" : "unauthorized");
    return ok;
  }
};

class Outputs {
 public:
  void begin() { pinMode(PIN_LED_GREEN,OUTPUT); pinMode(PIN_LED_RED,OUTPUT); pinMode(PIN_BUZZER,OUTPUT); }
  void update(SecurityState s, uint32_t now) {
    bool green=false, red=false, buzz=false; uint32_t phase;
    switch(s) {
      case DISARMED: case ARMED: green=true; break;
      case ALARM: phase=now%1000; red=true; buzz=phase<200 || (phase>=400 && phase<600); break;
      case TAMPER_ALARM: phase=now%1000; red=true; buzz=phase<700; break;
      case FAULT: phase=now%2000; red=true; buzz=phase<100; break;
      default: red=true; buzz=true;
    }
    digitalWrite(PIN_LED_GREEN,green); digitalWrite(PIN_LED_RED,red); digitalWrite(PIN_BUZZER,buzz);
  }
};

class PinInput {
  char value[16] = {}, stars[16] = {}; uint8_t length = 0;
 public:
  void clear() { length=0; value[0]=0; }
  void add(char k) { if (k>='0' && k<='9' && length<15) { value[length++]=k; value[length]=0; } }
  bool correct() const { return !strcmp(value, ARM_PIN); }
  const char *masked() { for(uint8_t i=0;i<length;++i) stars[i]='*'; stars[length]=0; return stars; }
};

Storage storage; Display display; Tamper tamper; Rfid rfid; Outputs outputs; PinInput pin;
Keypad keypad(makeKeymap(keypadLayout), keypadRowPins, keypadColPins, 4, 4);
SecurityState state = DISARMED, faultResume = ARMED;
bool rfidAuth = false; uint32_t authUntil = 0, lastRfidCheck = 0;
// Set only after both RFID and PIN succeed for an intrusion ALARM.
bool operatorChoicePending = false;
char notice[17] = {}; uint32_t noticeUntil = 0;

void clearAuth() { rfidAuth=false; authUntil=0; operatorChoicePending=false; pin.clear(); }
void saveState() { storage.save(state, faultResume); }
void notify(const char *s) { strncpy(notice,s,16); notice[16]=0; noticeUntil=millis()+NOTICE_DURATION_MS; }
void setState(SecurityState next) {
  if (!validState(next)) next=FAULT;
  if (next == state) return;
  DBG("State %s -> %s", stateName(state),stateName(next)); state=next; clearAuth(); saveState();
}
void enterFault(SecurityState resume) {
  if (!secureState(resume)) resume=ARMED;
  faultResume=resume;
  if (state != FAULT) { state=FAULT; clearAuth(); saveState(); }
}
void setFaultResume(SecurityState next) { if (secureState(next) && next != faultResume) { faultResume=next; saveState(); } }

void render(uint32_t now) {
  const char *a="", *b="";
  switch(state) {
    case DISARMED: a="SYSTEM DISARMED"; b=pin.masked()[0]?pin.masked():"ENTER PIN:"; break;
    case ARMED: a="SYSTEM ARMED"; b="MONITORING..."; break;
    case ALARM:
      a="!! INTRUSION !!";
      b=operatorChoicePending ? "A=ARM B=DISARM" : (rfidAuth ? "ENTER PIN:" : "SCAN RFID");
      break;
    case TAMPER_ALARM: a="!! TAMPER OPEN!!"; b=rfidAuth?"ENTER PIN:":"SCAN RFID"; break;
    case FAULT: a="!! SYSTEM FAULT!"; b="CHECK HARDWARE"; break;
    default: a="!! INVALID STATE"; b="FAIL SAFE";
  }
  display.show(a, activeUntil(noticeUntil,now) ? notice : b);
}

void enterPin() {
  bool correct=pin.correct();
  if (state == DISARMED) {
    pin.clear();
    if (!correct) { notify("INVALID PIN"); return; }
    if (!tamper.closed()) { notify("TAMPER OPEN"); return; }
    setState(ARMED); return;
  }
  if (state == ALARM || state == TAMPER_ALARM) {
    if (!rfidAuth) { pin.clear(); notify("SCAN RFID FIRST"); return; }
    if (!correct) { pin.clear(); notify("INVALID PIN"); return; }

    // Only a normal intrusion ALARM permits the authenticated operator to
    // choose whether the system rearms or disarms. Tamper alarms fail closed.
    if (state == ALARM) {
      pin.clear();
      operatorChoicePending = true;
      notify("AUTHENTICATED");
      return;
    }

    setState(ARMED);
  }
}
void scanKeypad() {
  char k=keypad.getKey(); if (k==NO_KEY) return;

  if (state == ALARM && operatorChoicePending) {
    if (k == 'A') {
      // Maintain the existing rule that an open tamper contact cannot rearm.
      if (!tamper.closed()) { setState(TAMPER_ALARM); return; }
      setState(ARMED);
    } else if (k == 'B') {
      setState(DISARMED);
    } else if (k == '*') {
      clearAuth();
      notify("AUTH CANCELLED");
    } else {
      notify("USE A OR B");
    }
    return;
  }

  if (k=='*') { pin.clear(); return; }
  if (k=='#') { enterPin(); return; }
  if (state==DISARMED || state==ALARM || state==TAMPER_ALARM) pin.add(k);
}
void monitorSensors() {
  if (state == ARMED) {
    if (!tamper.closed()) { setState(TAMPER_ALARM); return; }
    if (digitalRead(PIN_PIR) == HIGH) { setState(ALARM); return; }
  }
  if (state == FAULT) {
    if (!tamper.closed()) setFaultResume(TAMPER_ALARM);
    else if (faultResume==ARMED && digitalRead(PIN_PIR)==HIGH) setFaultResume(ALARM);
  }
}
void monitorRfid(uint32_t now) {
  if (now-lastRfidCheck < RFID_HEALTH_CHECK_MS) return;
  lastRfidCheck=now; bool ok=rfid.healthy();
  if (!ok && state != FAULT) { enterFault(secureState(state)?state:ARMED); return; }
  if (ok && state == FAULT) setState(faultResume); // never resumes DISARMED
}
void processRfid(uint32_t now) {
  if ((state==ALARM || state==TAMPER_ALARM) && rfid.authorized()) {
    rfidAuth=true; authUntil=now+RFID_AUTH_WINDOW_MS; pin.clear(); notify("RFID OK: PIN");
  }
  if (rfidAuth && !activeUntil(authUntil,now)) { clearAuth(); notify("RFID TIMED OUT"); }
}
void setupWatchdog() {
#if ESP_IDF_VERSION_MAJOR >= 5
  esp_task_wdt_config_t c; c.timeout_ms=WDT_TIMEOUT_SECONDS*1000; c.idle_core_mask=0; c.trigger_panic=true; esp_task_wdt_init(&c);
#else
  esp_task_wdt_init(WDT_TIMEOUT_SECONDS, true);
#endif
  esp_task_wdt_add(NULL);
}
void setup() {
  Serial.begin(115200);
  setupWatchdog();
  pinMode(PIN_PIR, INPUT);
  tamper.begin();
  outputs.begin();
  storage.begin();
  state = storage.state();
  faultResume = storage.resume();

  bool lcdOK = display.begin();
  bool rfidOK = rfid.begin();
  DBG("LCD: %s", lcdOK ? "OK" : "FAILED");
  DBG("RFID: %s", rfidOK ? "OK" : "FAILED");

  if (!lcdOK || !rfidOK) enterFault(secureState(state) ? state : faultResume);
  else if (state == FAULT) { state = faultResume; saveState(); }
  else if (!secureState(state) && state != DISARMED) { state = DISARMED; saveState(); }

  lastRfidCheck = millis();
  render(millis());
  DBG("Startup state: %s", stateName(state));
}
void loop() {
  uint32_t now=millis(); tamper.update(now); scanKeypad(); processRfid(now); monitorSensors(); monitorRfid(now);
  outputs.update(state,now); render(now); esp_task_wdt_reset();
}
