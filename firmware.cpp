// C++ code
//
#include <LiquidCrystal_I2C.h>
#include <Keypad.h>
#include <Wire.h>

const int pirPin = 34;
const int buzzPin = 25;
const byte ROWS = 4;
const byte COLS = 4;

char keys[ROWS][COLS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}};

byte rowPins[ROWS] = {13, 14, 27, 26};
byte colPins[COLS] = {4, 16, 17, 18};
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);
String correctPIN = ""; //Hardcoded correct credentials here
String enteredPIN = "";
int wrongAttempts = 0;
bool locked = false;
LiquidCrystal_I2C lcd(0x27, 16, 2);

void setup()
{
  Wire.begin(21,22);
  lcd.init();
  lcd.backlight();
  pinMode(pirPin, INPUT);
  pinMode(buzzPin, OUTPUT);
  lcd.backlight();
  lcd.setCursor(0, 0);
  lcd.print("Enter PIN:");
}

void loop()
{
  if (locked) {
  	return; }
  char key = keypad.getKey();
  if (key) {
    //'#' = Submit PIN
    if (key=='#') {
      if (enteredPIN == correctPIN) {
        lcd.clear();
        lcd.print("Correct PIN!");
        delay(2000);
        
        enteredPIN = "";
        lcd.clear();
        lcd.print("Enter PIN:");}
      else { 
        wrongAttempts++;
        lcd.clear();
        lcd.print("Wrong PIN!");
        delay(1000);
        lcd.clear();
        lcd.print("Attempts left: " + String(3 - wrongAttempts));
        enteredPIN = "";
        if (wrongAttempts >=3) {
          locked = true;
          lcd.clear();
          lcd.print("SYSTEM LOCKED");
          tone(buzzPin, 1000);
        }
      }
    }
    // '*' = clear entered PIN
    else if (key =='*') {
      enteredPIN = "";
      lcd.clear();
      lcd.print("Enter PIN:");
      }
    //Only accept number keys
    else if(key>='0' && key<='9') {
      enteredPIN+=key;
      lcd.setCursor(0,1);
      //Display * instead of the actual PIN
      for (int i=0; i<enteredPIN.length(); i++) {
        lcd.print("*");
      }
    }
  }
  int motion = digitalRead(pirPin);
  if (motion==HIGH) {
  	tone(buzzPin, 1000);
  } else {
  	noTone(buzzPin);
  }
}
