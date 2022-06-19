
#include <Servo.h>


const int Bup = 3;
const int Bdown = 2;
const int PWMB = 7;

const int Aup = 5;
const int Adown = 4;
const int PWMA = 6;

// Muuttujat valosensoria varten
const int sensor0 = A0;
const int sensor1 = A1;
const int sensor2 = A2;
const int sensor3 = A3;
const int sensor4 = A4;
const int sensor5 = A5;


// Moottoreihin liittyvä määritys
unsigned long int timeA = millis();
unsigned long int timeB = millis();

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



//Kaikki pinit ulossyöttöjä

 pinMode(Aup, OUTPUT);
 pinMode(Adown, OUTPUT);
 pinMode(PWMA, OUTPUT);

 pinMode(Bup, OUTPUT);
 pinMode(Bdown, OUTPUT);
 pinMode(PWMB, OUTPUT);

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
  static unsigned long lastTime = 0;
  const long interval = 10;
  static bool state = 0;

  unsigned long now = millis();
  if ( now - lastTime >= interval && state == 1) {
	state = 0;
	lastTime = now;
	stopMoottorit();
  }
 
  else if ( now - lastTime > interval && state == 0) {
	state = 1;
	lastTime = now;
	digitalWrite(Aup, HIGH);
	digitalWrite(Adown, LOW);
	analogWrite(PWMA, nopeus);
    
  }
 

 }
 
 void eteenpainMotB(int nopeus) {
  static unsigned long lastTime = 0;
  const long interval = 10;
  static bool state = 0;

  unsigned long now = millis();

  if ( now - lastTime >= interval && state == 1) {
	state = 0;
	lastTime = now;
	stopMoottorit();
  }

  else if ( now - lastTime > interval && state == 0) {
	state = 1;
	lastTime = now;
	digitalWrite(Bup, HIGH);
	digitalWrite(Bdown, LOW);
	analogWrite(PWMB, nopeus);
    
  }
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

void eteenpainMotAB(int nopeus) {
  static unsigned long lastTime = 0;
  const long interval = 10;
  static bool state = 0;

  unsigned long now = millis();

  if ( now - lastTime >= interval && state == 1) {
	state = 0;
	lastTime = now;
	stopMoottorit();
  }

  else if ( now - lastTime > interval && state == 0) {
	state = 1;
	lastTime = now;
	digitalWrite(Aup, HIGH);
	digitalWrite(Adown, LOW);
	analogWrite(PWMA, nopeus);
	digitalWrite(Bup, HIGH);
	digitalWrite(Bdown, LOW);
	analogWrite(PWMB, nopeus);
    
  }
}

  void ballServo() {
	static unsigned long lastTime = 0;
	const long interval = 500;
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
	myservo.write(0);
    
  }
 }

    
 

void loop() {
  // Sensorien yhteisarvo
  inputValue = (1*analogRead(sensor1)) + (0.5*analogRead(sensor2)) + (0*analogRead(sensor3)) + (-0.5*analogRead(sensor4)) + (-1*analogRead(sensor5));


 //Arvoista keskiarvon laskeminen
 
   // subtract the last reading:
  total = total - readings[readIndex];
  // read from the sensor:
  readings[readIndex] = inputValue;
  // add the reading to the total:
  total = total + readings[readIndex];
  // advance to the next position in the array:
  readIndex = readIndex + 1;

  // if we're at the end of the array...
  if (readIndex >= numReadings) {
	// ...wrap around to the beginning:
	readIndex = 0;
  }

  // calculate the average:
  average = total / numReadings;
 

 
 if (average < -50) {
	eteenpainMotA(255);
	myservo.write(90);
	Serial.println("A");
 }
 
 else if (average > 50) {
	eteenpainMotB(255);
	myservo.write(90);
	Serial.println("B");
    
 }
 
 // Jos edessä enemmän valoa
 else if ((analogRead(sensor3)-analogRead(sensor0) > 0)) {
	eteenpainMotAB(255);
	ballServo();
	Serial.println("AB");
    
 }
 
 else {
  stopMoottorit();
  myservo.write(90);
  Serial.println("STOP");
 }
 
 

 Serial.println(analogRead(sensor3)-analogRead(sensor0));
 
 
 }

