/*
  ESP32 Intrusion Detection System
  Board: ESP32-WROOM-32 / 30-pin DevKit

  Security properties:
  - PIN arms only from DISARMED.
  - A tamper-open enclosure cannot be armed.
  - Clearing ALARM or TAMPER_ALARM requires an authorized RFID scan
    followed by the correct PIN within RFID_AUTH_WINDOW_MS.
  - PIN-only and RFID-only alarm clearing are impossible.
  - Security state is saved only on state transitions.
  - ARMED, ALARM, and TAMPER_ALARM survive reboot/power loss.
*/

#include <Arduino.h>
#include <Wire.h>
#include <SPI.h>
#include <Preferences.h>
#include <LiquidCrystal_I2C.h>
#include <Keypad.h>
#include <MFRC522.h>
#include <esp_task_wdt.h>
#include <esp_idf_version.h>

// ============================================================================
// CONFIGURATION: change values in this section for your installation
// ============================================================================

static const bool DEBUG_ENABLED = true;

// Do not print this PIN in logs. Change before deployment.
static const char ARM_PIN[] = "1234";

// Example UID. Change to the byte UID of the authorized card.
// Supported UID lengths: 4, 7, or 10 bytes.
static const byte AUTHORIZED_UID[] = {0xDE, 0xAD, 0xBE, 0xEF};
static const byte AUTHORIZED_UID_LENGTH = sizeof(AUTHORIZED_UID);

// LCD settings.
static const uint8_t LCD_I2C_ADDRESS = 0x27;
static const uint8_t LCD_COLUMNS = 16;
static const uint8_t LCD_ROWS = 2;

// GPIO assignments. Avoids ESP32 flash pins and boot/strapping pins.
static const uint8_t PIN_LCD_SDA = 21;
static const uint8_t PIN_LCD_SCL = 22;

static const uint8_t PIN_RFID_SCK  = 18;
static const uint8_t PIN_RFID_MISO = 19;
static const uint8_t PIN_RFID_MOSI = 23;
static const uint8_t PIN_RFID_SS   = 27;
// MFRC522 RST is wired permanently to 3.3 V.

static const uint8_t PIN_PIR = 4;
static const uint8_t PIN_TAMPER = 33;
static const uint8_t PIN_LED_GREEN = 25;
static const uint8_t PIN_LED_RED = 26;
static const uint8_t PIN_BUZZER = 32;

static const byte KEYPAD_ROWS = 4;
static const byte KEYPAD_COLS = 4;
static byte keypadRowPins[KEYPAD_ROWS] = {13, 14, 16, 17};
static byte keypadColPins[KEYPAD_COLS] = {34, 35, 36, 39};

// GPIO 34/35/36/39 need external 10 kOhm pull-ups to 3.3 V.
static char keypadLayout[KEYPAD_ROWS][KEYPAD_COLS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};

// Tamper contact polarity.
// NC contact wired GPIO -> magnetic contact -> GND, with INPUT_PULLUP:
// closed enclosure = LOW; open/disconnected cable = HIGH.
static const uint8_t TAMPER_CLOSED_LEVEL = LOW;

// Timings.
static const uint32_t TAMPER_DEBOUNCE_MS = 50;
static const uint32_t RFID_HEALTH_CHECK_MS = 5000;
static const uint32_t RFID_AUTH_WINDOW_MS = 30000;
static const uint32_t NOTICE_DURATION_MS = 1500;
static const uint32_t WDT_TIMEOUT_SECONDS = 10;

// ============================================================================
// Debug support
// ============================================================================

#define DBG(fmt, ...)                                                        \
  do {                                                                        \
    if (DEBUG_ENABLED) {                                                      \
      Serial.printf("[IDS] " fmt "\n", ##__VA_ARGS__);                        \
    }                                                                         \
  } while (0)

// ============================================================================
// State and helpers
// ============================================================================

enum SecurityState : uint8_t {
  DISARMED = 0,
  ARMED = 1,
  ALARM = 2,
  TAMPER_ALARM = 3,
  FAULT = 4
};

static bool timeActive(uint32_t until, uint32_t now) {
  return (int32_t)(until - now) > 0;
}

static bool isSecureState(SecurityState state) {
  return state == ARMED || state == ALARM || state == TAMPER_ALARM;
}

static bool validState(uint8_t raw) {
  return raw <= FAULT;
}

static const char *stateName(SecurityState state) {
  switch (state) {
    case DISARMED:     return "DISARMED";
    case ARMED:        return "ARMED";
    case ALARM:        return "ALARM";
    case TAMPER_ALARM: return "TAMPER_ALARM";
    case FAULT:        return "FAULT";
    default:           return "INVALID";
  }
}

// ============================================================================
// Persistent storage
// ============================================================================

class SecurityStorage {
public:
  void begin() {
    preferences.begin("intrusion", false);
  }

  void save(SecurityState state, SecurityState resumeState) {
    preferences.putUChar("state", static_cast<uint8_t>(state));
    preferences.putUChar("resume", static_cast<uint8_t>(resumeState));
  }

  SecurityState loadState() {
    uint8_t raw = preferences.getUChar("state", DISARMED);
    return validState(raw) ? static_cast<SecurityState>(raw) : DISARMED;
  }

  SecurityState loadResumeState() {
    uint8_t raw = preferences.getUChar("resume", ARMED);
    SecurityState state = validState(raw)
                            ? static_cast<SecurityState>(raw)
                            : ARMED;
    return isSecureState(state) ? state : ARMED;
  }

private:
  Preferences preferences;
};

// ============================================================================
// LCD
// ============================================================================

class Display {
public:
  Display() : lcd(LCD_I2C_ADDRESS, LCD_COLUMNS, LCD_ROWS), available(false) {
    previous[0][0] = '\0';
    previous[1][0] = '\0';
  }

  bool begin() {
    Wire.begin(PIN_LCD_SDA, PIN_LCD_SCL);

    Wire.beginTransmission(LCD_I2C_ADDRESS);
    if (Wire.endTransmission() != 0) {
      DBG("LCD not found at 0x%02X", LCD_I2C_ADDRESS);
      return false;
    }

    lcd.init();
    lcd.backlight();
    available = true;
    show("INITIALIZING...", "");
    return true;
  }

  void show(const char *line1, const char *line2) {
    if (!available) {
      return;
    }
    writeLine(0, line1);
    writeLine(1, line2);
  }

private:
  LiquidCrystal_I2C lcd;
  bool available;
  char previous[2][17];

  void writeLine(uint8_t row, const char *text) {
    char padded[17];
    memset(padded, ' ', 16);
    padded[16] = '\0';

    if (text != nullptr) {
      for (uint8_t i = 0; i < 16 && text[i] != '\0'; ++i) {
        padded[i] = text[i];
      }
    }

    if (strcmp(padded, previous[row]) == 0) {
      return;
    }

    lcd.setCursor(0, row);
    lcd.print(padded);
    strncpy(previous[row], padded, sizeof(previous[row]));
    previous[row][16] = '\0';
  }
};

// ============================================================================
// Debounced tamper sensor
// ============================================================================

class TamperSensor {
public:
  TamperSensor() : stableLevel(HIGH), candidateLevel(HIGH), changedAt(0) {}

  void begin() {
    pinMode(PIN_TAMPER, INPUT_PULLUP);
    stableLevel = digitalRead(PIN_TAMPER);
    candidateLevel = stableLevel;
    changedAt = millis();
  }

  void update(uint32_t now) {
    uint8_t raw = digitalRead(PIN_TAMPER);

    if (raw != candidateLevel) {
      candidateLevel = raw;
      changedAt = now;
    }

    if (candidateLevel != stableLevel &&
        now - changedAt >= TAMPER_DEBOUNCE_MS) {
      stableLevel = candidateLevel;
      DBG("Tamper now %s", isClosed() ? "closed" : "open");
    }
  }

  bool isClosed() const {
    return stableLevel == TAMPER_CLOSED_LEVEL;
  }

private:
  uint8_t stableLevel;
  uint8_t candidateLevel;
  uint32_t changedAt;
};

// ============================================================================
// RFID
// ============================================================================

class RfidReader {
public:
  RfidReader() : reader(PIN_RFID_SS, MFRC522::UNUSED_PIN) {}

  bool begin() {
    SPI.begin(PIN_RFID_SCK, PIN_RFID_MISO, PIN_RFID_MOSI, PIN_RFID_SS);
    reader.PCD_Init();

    bool ok = healthy();
    DBG("RFID %s", ok ? "online" : "offline");
    return ok;
  }

  bool healthy() {
    byte version = reader.PCD_ReadRegister(MFRC522::VersionReg);
    // 0x00 and 0xFF normally indicate missing/broken SPI communication.
    return version != 0x00 && version != 0xFF;
  }

  bool authorizedCardPresented() {
    if (!reader.PICC_IsNewCardPresent() || !reader.PICC_ReadCardSerial()) {
      return false;
    }

    bool authorized = reader.uid.size == AUTHORIZED_UID_LENGTH;

    if (authorized) {
      for (byte i = 0; i < AUTHORIZED_UID_LENGTH; ++i) {
        if (reader.uid.uidByte[i] != AUTHORIZED_UID[i]) {
          authorized = false;
          break;
        }
      }
    }

    reader.PICC_HaltA();
    reader.PCD_StopCrypto1();

    DBG("RFID card %s", authorized ? "authorized" : "unauthorized");
    return authorized;
  }

private:
  MFRC522 reader;
};

// ============================================================================
// Alarm indicators and buzzer
// ============================================================================

class AlarmOutputs {
public:
  void begin() {
    pinMode(PIN_LED_GREEN, OUTPUT);
    pinMode(PIN_LED_RED, OUTPUT);
    pinMode(PIN_BUZZER, OUTPUT);
    digitalWrite(PIN_LED_GREEN, LOW);
    digitalWrite(PIN_LED_RED, LOW);
    digitalWrite(PIN_BUZZER, LOW);
  }

  void update(SecurityState state, uint32_t now) {
    bool green = false;
    bool red = false;
    bool buzzer = false;

    switch (state) {
      case DISARMED:
      case ARMED:
        green = true;
        break;

      case ALARM: {
        red = true;
        uint32_t phase = now % 1000;
        buzzer = (phase < 200) || (phase >= 400 && phase < 600);
        break;
      }

      case TAMPER_ALARM: {
        red = true;
        uint32_t phase = now % 1000;
        buzzer = phase < 700;
        break;
      }

      case FAULT: {
        red = true;
        uint32_t phase = now % 2000;
        buzzer = phase < 100;
        break;
      }

      default:
        // Invalid state fails closed.
        red = true;
        buzzer = true;
        break;
    }

    digitalWrite(PIN_LED_GREEN, green ? HIGH : LOW);
    digitalWrite(PIN_LED_RED, red ? HIGH : LOW);
    digitalWrite(PIN_BUZZER, buzzer ? HIGH : LOW);
  }
};

// ============================================================================
// Keypad / PIN authentication
// ============================================================================

class PinInput {
public:
  PinInput() : length(0) {
    clear();
  }

  void clear() {
    length = 0;
    entered[0] = '\0';
  }

  void append(char key) {
    if (key < '0' || key > '9') {
      return;
    }

    if (length < sizeof(entered) - 1) {
      entered[length++] = key;
      entered[length] = '\0';
    }
  }

  bool matchesConfiguredPin() const {
    return strcmp(entered, ARM_PIN) == 0;
  }

  const char *masked() {
    for (uint8_t i = 0; i < length; ++i) {
      mask[i] = '*';
    }
    mask[length] = '\0';
    return mask;
  }

private:
  char entered[16];
  char mask[16];
  uint8_t length;
};

// ============================================================================
// Globals
// ============================================================================

Display display;
SecurityStorage storage;
TamperSensor tamper;
RfidReader rfid;
AlarmOutputs outputs;

Keypad keypad = Keypad(
  makeKeymap(keypadLayout),
  keypadRowPins,
  keypadColPins,
  KEYPAD_ROWS,
  KEYPAD_COLS
);

SecurityState currentState = DISARMED;
SecurityState faultResumeState = ARMED;
PinInput pinInput;

bool rfidAuthenticated = false;
uint32_t rfidAuthenticatedUntil = 0;
uint32_t lastRfidHealthCheck = 0;

char notice[17] = "";
uint32_t noticeUntil = 0;

// ============================================================================
// State transitions
// ============================================================================

void showNotice(const char *message) {
  strncpy(notice, message, 16);
  notice[16] = '\0';
  noticeUntil = millis() + NOTICE_DURATION_MS;
}

void clearAuthentication() {
  rfidAuthenticated = false;
  rfidAuthenticatedUntil = 0;
  pinInput.clear();
}

void saveCurrentState() {
  storage.save(currentState, faultResumeState);
}

void enterState(SecurityState nextState) {
  if (!validState(static_cast<uint8_t>(nextState))) {
    nextState = FAULT;
  }

  if (currentState == nextState) {
    return;
  }

  DBG("State %s -> %s", stateName(currentState), stateName(nextState));
  currentState = nextState;
  clearAuthentication();
  saveCurrentState();
}

void enterFault(SecurityState resumeState) {
  if (!isSecureState(resumeState)) {
    resumeState = ARMED;
  }

  faultResumeState = resumeState;

  if (currentState != FAULT) {
    DBG("Entering FAULT; resume target %s", stateName(faultResumeState));
    currentState = FAULT;
    clearAuthentication();
    saveCurrentState();
  }
}

void updateFaultResumeState(SecurityState nextResumeState) {
  if (!isSecureState(nextResumeState) ||
      faultResumeState == nextResumeState) {
    return;
  }

  faultResumeState = nextResumeState;
  saveCurrentState();
}

// ============================================================================
// UI
// ============================================================================

void renderUi(uint32_t now) {
  const char *line1 = "";
  const char *line2 = "";

  switch (currentState) {
    case DISARMED:
      line1 = "SYSTEM DISARMED";
      line2 = (pinInput.masked()[0] != '\0') ? pinInput.masked() : "ENTER PIN:";
      break;

    case ARMED:
      line1 = "SYSTEM ARMED";
      line2 = "MONITORING...";
      break;

    case ALARM:
      line1 = "!! INTRUSION !!";
      line2 = rfidAuthenticated ? "ENTER PIN:" : "SCAN RFID";
      break;

    case TAMPER_ALARM:
      line1 = "!! TAMPER OPEN!!";
      line2 = rfidAuthenticated ? "ENTER PIN:" : "SCAN RFID";
      break;

    case FAULT:
      line1 = "!! SYSTEM FAULT!";
      line2 = "CHECK HARDWARE";
      break;

    default:
      line1 = "!! INVALID STATE";
      line2 = "FAIL SAFE";
      break;
  }

  if (timeActive(noticeUntil, now)) {
    line2 = notice;
  }

  display.show(line1, line2);
}

// ============================================================================
// Security handling
// ============================================================================

void handlePinEnter() {
  bool correct = pinInput.matchesConfiguredPin();

  if (currentState == DISARMED) {
    if (!correct) {
      showNotice("INVALID PIN");
      pinInput.clear();
      return;
    }

    pinInput.clear();

    if (!tamper.isClosed()) {
      showNotice("TAMPER OPEN");
      return;
    }

    enterState(ARMED);
    return;
  }

  if (currentState == ALARM || currentState == TAMPER_ALARM) {
    if (!rfidAuthenticated) {
      showNotice("SCAN RFID FIRST");
      pinInput.clear();
      return;
    }

    if (!correct) {
      showNotice("INVALID PIN");
      pinInput.clear();
      return;
    }

    // Both factors have now succeeded.
    enterState(ARMED);
    return;
  }

  pinInput.clear();
}

void handleKeypad() {
  char key = keypad.getKey();
  if (key == NO_KEY) {
    return;
  }

  if (key == '*') {
    pinInput.clear();
    return;
  }

  if (key == '#') {
    handlePinEnter();
    return;
  }

  // Only accept numeric PIN input in states that authenticate.
  if (currentState == DISARMED ||
      currentState == ALARM ||
      currentState == TAMPER_ALARM) {
    pinInput.append(key);
  }
}

void handleRfid(uint32_t now) {
  if (currentState != ALARM && currentState != TAMPER_ALARM) {
    return;
  }

  if (!rfid.authorizedCardPresented()) {
    return;
  }

  rfidAuthenticated = true;
  rfidAuthenticatedUntil = now + RFID_AUTH_WINDOW_MS;
  pinInput.clear();
  showNotice("RFID OK: PIN");
}

void expireAuthentication(uint32_t now) {
  if (rfidAuthenticated && !timeActive(rfidAuthenticatedUntil, now)) {
    clearAuthentication();
    showNotice("RFID TIMED OUT");
  }
}

void monitorSensors() {
  if (currentState == ARMED) {
    if (!tamper.isClosed()) {
      enterState(TAMPER_ALARM);
      return;
    }

    if (digitalRead(PIN_PIR) == HIGH) {
      enterState(ALARM);
      return;
    }
  }

  // Maintain fail-safe state if a fault is active while another incident occurs.
  if (currentState == FAULT) {
    if (!tamper.isClosed()) {
      updateFaultResumeState(TAMPER_ALARM);
    } else if (faultResumeState == ARMED && digitalRead(PIN_PIR) == HIGH) {
      updateFaultResumeState(ALARM);
    }
  }
}

void monitorRfidHealth(uint32_t now) {
  if (now - lastRfidHealthCheck < RFID_HEALTH_CHECK_MS) {
    return;
  }

  lastRfidHealthCheck = now;
  bool healthy = rfid.healthy();

  if (!healthy && currentState != FAULT) {
    SecurityState resume = isSecureState(currentState)
                             ? currentState
                             : ARMED;
    enterFault(resume);
    return;
  }

  // Recover only to the stored security state, never to DISARMED.
  if (healthy && currentState == FAULT) {
    DBG("RFID recovered; returning to %s", stateName(faultResumeState));
    enterState(faultResumeState);
  }
}

// ============================================================================
// Watchdog
// ============================================================================

void setupWatchdog() {
#if ESP_IDF_VERSION_MAJOR >= 5
  esp_task_wdt_config_t config;
  config.timeout_ms = WDT_TIMEOUT_SECONDS * 1000;
  config.idle_core_mask = 0;
  config.trigger_panic = true;
  esp_task_wdt_init(&config);
#else
  esp_task_wdt_init(WDT_TIMEOUT_SECONDS, true);
#endif

  esp_task_wdt_add(NULL);
}

// ============================================================================
// Arduino setup/loop
// ============================================================================

void setup() {
  Serial.begin(115200);
  DBG("Intrusion detector starting");

  setupWatchdog();

  pinMode(PIN_PIR, INPUT);
  tamper.begin();
  outputs.begin();

  storage.begin();

  // Read state before peripheral initialization so it can be restored safely.
  currentState = storage.loadState();
  faultResumeState = storage.loadResumeState();

  bool lcdOk = display.begin();
  bool rfidOk = rfid.begin();

  if (!lcdOk || !rfidOk) {
    SecurityState secureResume = isSecureState(currentState)
                                   ? currentState
                                   : faultResumeState;
    enterFault(secureResume);
  } else if (currentState == FAULT) {
    // Restore the recorded secure state only after successful health checks.
    currentState = faultResumeState;
    saveCurrentState();
  } else if (!isSecureState(currentState) && currentState != DISARMED) {
    currentState = DISARMED;
    saveCurrentState();
  }

  lastRfidHealthCheck = millis();
  renderUi(millis());
  DBG("Startup state: %s", stateName(currentState));
}

void loop() {
  const uint32_t now = millis();

  tamper.update(now);
  handleKeypad();
  handleRfid(now);
  expireAuthentication(now);
  monitorSensors();
  monitorRfidHealth(now);

  outputs.update(currentState, now);
  renderUi(now);

  // Main loop remains non-blocking; reset watchdog every completed pass.
  esp_task_wdt_reset();
}
