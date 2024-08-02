// Import the functions you need from the SDKs you need
import { getAnalytics } from "firebase/analytics";
const { initializeApp, applicationDefault, cert } = require('firebase-admin/app');
const { getFirestore, Timestamp, FieldValue, Filter ,getDocs} = require('firebase-admin/firestore');

const firebaseConfig = {
    apiKey: "AIzaSyBrENJrtSDXitYrJsl-q9tSUYreEeC1dvY",
    authDomain: "my-project-330911.firebaseapp.com",
    projectId: "my-project-330911",
    storageBucket: "my-project-330911.appspot.com",
    messagingSenderId: "700384697462",
    appId: "1:700384697462:web:ea55492c80311ef5401357",
    measurementId: "G-ELBLJ40NVY"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const db = getFirestore(app);