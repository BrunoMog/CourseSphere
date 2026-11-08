const env = (import.meta as any).env || {};

export default {
  apiKey: env.VITE_FIREBASE_API_KEY || "PLACEHOLDER_FIREBASE_API_KEY",
  authDomain: env.VITE_FIREBASE_AUTH_DOMAIN || "coursesphere-8bd9a.firebaseapp.com",
  databaseURL: env.VITE_FIREBASE_DATABASE_URL || "https://coursesphere-8bd9a-default-rtdb.firebaseio.com",
  projectId: env.VITE_FIREBASE_PROJECT_ID || "coursesphere-8bd9a",
  storageBucket: env.VITE_FIREBASE_STORAGE_BUCKET || "coursesphere-8bd9a.appspot.com",
  messagingSenderId: env.VITE_FIREBASE_MESSAGING_SENDER_ID || "728789297654",
  appId: env.VITE_FIREBASE_APP_ID || "1:728789297654:web:6b699e8b5ebebc8a8d3fd7",
  measurementId: env.VITE_FIREBASE_MEASUREMENT_ID || "G-PM7PMGBE0R"
};
