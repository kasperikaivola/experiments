#include <Servo.h>

const int Bup = 3;
const int Bdown = 2;
const int PWMB = 7;

const int Aup = 5;
const int Adown = 4;
const int PWMA = 6;

const int switchPin = 8;
const int ledPin = 9;
int ledState = LOW;
bool extraState = 1;
bool flag0 = 0;
long lastTime2 = 0;


// Muuttujat valosensoria varten
const int sensor0 = A0;
const int sensor1 = A1;
const int sensor2 = A2;
const int sensor3 = A3;
const int sensor4 = A4;
const int sensor5 = A5;


// Lukuvektorin koko
const int numReadings = 25;

int readings[numReadings];
int readIndex = 0;
int total = 0;
int average = 0;

int inputValue = 0;

// Servon alustukset
Servo myservo;

#define servoPin 11

int angle = 0;




void setup(){



//Pinien määrittely

 pinMode(Aup, OUTPUT);
 pinMode(Adown, OUTPUT);
 pinMode(PWMA, OUTPUT);

 pinMode(Bup, OUTPUT);
 pinMode(Bdown, OUTPUT);
 pinMode(PWMB, OUTPUT);

 pinMode(switchPin, INPUT);
 pinMode(ledPin, OUTPUT);

 // initialize serial communication with computer:
 Serial.begin(9600);
 // initialize all the readings to 0:
 for (int thisReading = 0; thisReading < numReadings; thisReading++) {
   readings[thisReading] = 0;
  }

 // Servo
 myservo.attach(servoPin);
 
}


 void eteenpainMotA(int nopeus) {

	digitalWrite(Aup, HIGH);
	digitalWrite(Adown, LOW);
	analogWrite(PWMA, nopeus);
	digitalWrite(Bup, LOW);
	digitalWrite(Bdown, LOW);
	analogWrite(PWMB, 0);
	}
 
 void eteenpainMotB(int nopeus) {

	digitalWrite(Aup, LOW);
	digitalWrite(Adown, LOW);
	analogWrite(PWMA, 0);
	digitalWrite(Bup, HIGH);
	digitalWrite(Bdown, LOW);
	analogWrite(PWMB, nopeus);
	}

  void stopMoottorit() {
	// A-moottori
	digitalWrite(Aup, LOW);
	digitalWrite(Adown, LOW);
	analogWrite(PWMA, 0);

	// B-moottori
	digitalWrite(Bup, LOW);
	digitalWrite(Bdown, LOW);
	analogWrite(PWMB, 0);
  }

void eteenpainMotAB(int nopeusA, int nopeusB) {

	digitalWrite(Aup, HIGH);
	digitalWrite(Adown, LOW);
	analogWrite(PWMA, nopeusA);
	digitalWrite(Bup, HIGH);
	digitalWrite(Bdown, LOW);
	analogWrite(PWMB, nopeusB);
    
  }


 void taaksepainMotA(int nopeus) {

	digitalWrite(Aup, LOW);
	digitalWrite(Adown, HIGH);
	analogWrite(PWMA, nopeus);
	digitalWrite(Bup, LOW);
	digitalWrite(Bdown, LOW);
	analogWrite(PWMB, 0);
	delay(150);
	}

  void ballServo() {
	static unsigned long lastTime = 0;
	const long interval = 1500;
	static bool state = 0;
	unsigned long now = millis();

  if ( now - lastTime >= interval && state == 1) {
	state = 0;
	lastTime = now;
	myservo.write(90);
	}

  else if ( now - lastTime > interval && state == 0) {
	state = 1;
	lastTime = now;
	myservo.write(25);
	}
    
  }

  void ledBlink() {
  if(flag0 == 1 && extraState == 1) {
    lastTime2 = millis();
    ledState = HIGH;
    extraState = 0;
    flag0 = 0;
  }

  if(millis() - lastTime2 > 1000) {
    ledState = LOW;
    extraState = 1;
  }

  if(millis() - lastTime2 > 400) {
    ledState = HIGH;
  }
  
  if(millis() - lastTime2 > 250) {
    ledState = LOW;
    
  }
}

 

void loop() {
  // Sensorien painotettu summa, jolla toimenpiteet määritetään
  inputValue = (1*analogRead(sensor1)) + (0.5*analogRead(sensor2)) + (-0.5*analogRead(sensor4)) + (-1*analogRead(sensor5));


 //Arvoista keskiarvon laskeminen mittauksen tasoittamiseksi
 
  total = total - readings[readIndex];
  readings[readIndex] = inputValue;
  total = total + readings[readIndex];
  readIndex = readIndex + 1;
  if (readIndex >= numReadings) {
	readIndex = 0;
  }
  // Keskiarvo
  average = total / numReadings;


 
 // Ajamisen suunta
 
 if (average < -120) {
	eteenpainMotA(230);
 }

 else if (average > 120) {
	eteenpainMotB(200);
 }

 // Jos edessä valoa
 else if ((analogRead(sensor3)-analogRead(sensor0) > 20)) {
	eteenpainMotAB(250, 155); // Eri nopeudet, koska robotin painopiste ei ole keskellä
	if (digitalRead(switchPin)==HIGH) {
  	ballServo();
flag0 = 1;
	}
 }

// Jos takana valoa
 else if ((analogRead(sensor3)-analogRead(sensor0) < -50)) {
	taaksepainMotA(200);
 }

// Jos muut eivät toteudu, ei mene muuten kuin jos ei näy valoa missään
 else {
  stopMoottorit();
 }
 
 ledBlink();
 digitalWrite(ledPin, ledState);

 Serial.println(analogRead(sensor3)-analogRead(sensor0));
 //Serial.println(average);
 
 }

