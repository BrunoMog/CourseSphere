import $ from 'jquery';
import firebaseConfig from "./firebaseConfig";
import { FirebaseApp, initializeApp } from "firebase/app";
import { Database, getDatabase } from "firebase/database";
import { Auth, getAuth, onAuthStateChanged, signInWithEmailAndPassword } from "firebase/auth";
import { toast } from "react-toastify";

const app: FirebaseApp = initializeApp(firebaseConfig);
const database: Database = getDatabase(app);
const auth: Auth = getAuth();

const API_BASE_URL: string = ((import.meta as any).env && (import.meta as any).env.VITE_API_BASE_URL) || "";


async function createUser(email: string, password: string) {
  const response = await fetch(`${API_BASE_URL}/users/create`, {
    method: 'POST',
    mode: "cors",
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, password })
  });
  const json = await response.json();
  return json;
}


function performSignup() {
  const email: string = String($("#signup-email-input").val() || "");
  const password: string = String($("#signup-password-input").val() || "");

  createUser(email, password)
    .then(() => {
      signInWithEmailAndPassword(auth, email, password)
        .then(() => {
          window.location.replace("/");
        });
    })
    .catch((e) => {
      toast(`Sign up failed: ${e}`, {
        position: "top-right",
        hideProgressBar: true,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light"
      });
    });
}

/**
 * This function performs the user login transaction with firebase.
 */
function performLogin() {
  const email: string = String($("#login-email-input").val() || "");
  const password: string = String($("#login-password-input").val() || "");
  signInWithEmailAndPassword(auth, email, password)
    .then(() => {
      window.location.replace("/");
    })
    .catch((e) => {
      toast.error(`Login failed: ${e.message}`);
    });
}


/**
 * Sets the profile information if the user is logged in.
 * Fixed VULN-04: Transmits Bearer token in Authorization header instead of URL query string.
 */
async function setProfileInfoIfLoggedIn(
  setMajors: Function,
  setMinors: Function,
  setYear: Function,
  setCollege: Function,
  setCourses: Function,
  setAbout: Function
) {
  onAuthStateChanged(auth, async (user) => {
    if (!ensureUserLoggedIn()) return;
    const idToken = await user?.getIdToken();

    try {
      const response = await fetch(`${API_BASE_URL}/users/info`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${idToken}`
        }
      });

      const data = await response.json();

      if (data["majors"]) {
        setMajors(data["majors"]);
      }
      if (data["minors"]) {
        setMinors(data["minors"]);
      }
      if (data["year"]) {
        setYear(data["year"]);
      }
      if (data["college"]) {
        setCollege(data["college"]);
      }
      if (data["courses"]) {
        setCourses(data["courses"]);
      }
      if (data["about"]) {
        $("#info-output").val(data["about"]);
        setAbout(data["about"]);
      }
    } catch (e) {
      toast.error(`Failed to fetch data: ${e}`);
    }
  });
}

/**
 * Saves any profile changes that occur on the user dashboard.
 */
async function saveProfileChanges(majors: string[], minors: string[], courses: string[]) {
  if (!ensureUserLoggedIn()) return;
  const user = auth.currentUser;
  const about = $("#info-output").val();
  const year = $("#year-output").val();
  const college = $("#college-output").val();
  const idToken = await user?.getIdToken();

  const data = {
    majors: majors,
    minors: minors,
    year: year,
    college: college,
    courses: courses,
    about: about
  };

  fetch(`${API_BASE_URL}/users/info`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${idToken}`
    },
    body: JSON.stringify(data)
  })
    .then(() => {
      toast.success("Successfully saved your information!");
    })
    .catch((e: Error) => {
      toast.error(`Failed to save your information: ${e}`);
    });
}


/**
 * Sends the query and the authenticated user's Bearer token to the backend.
 * Fixed missing 'await' on user?.getIdToken() and removed unsanitized query reflection.
 */
async function fetchCourseSphereResponse(query: string) {
  const user = auth.currentUser;
  const idToken = await user?.getIdToken();
  const data = { query };
  const response = await fetch(`${API_BASE_URL}/users/query`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${idToken}`
    },
    body: JSON.stringify(data)
  })
    .then(response => response.json())
    .then(result => {
      toast.success("Successfully retrieved bot response!");
      return {
        botResponse: result.botResponse,
        newRecommendations: result.newRecommendations || []
      };
    })
    .catch((error: Error) => {
      console.error("Failed to fetch bot response:", error);
      toast.error(`Failed to fetch bot response: ${error.message}`);
      return {
        botResponse: "Unsupported Query",
        newRecommendations: []
      };
    });
  return response;
}

function ensureUserLoggedIn(): boolean {
  const user = auth.currentUser;
  if (user == null) {
    alert("Not logged in");
    return false;
  }
  return true;
}


async function saveCourseSphereChat(chatId: string, messages: Message[]) {
  if (!ensureUserLoggedIn()) return;

  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_BASE_URL}/chats/${encodeURIComponent(chatId)}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`
    },
    body: JSON.stringify({
      messages: messages.map(message => ({
        sender: message.sender,
        content: message.content,
        messageID: message.messageID,
        timestamp: message.timestamp
      }))
    })
  });

  const data = await response.json();
  if (!response.ok) {
    alert(data.error || 'Error saving messages');
  }
}


async function updateCourseSphereChat(chatId: string, messageId: string, updatedContent: string) {
  if (!ensureUserLoggedIn()) return;
  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_BASE_URL}/chats/${encodeURIComponent(chatId)}/messages/${encodeURIComponent(messageId)}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`
    },
    body: JSON.stringify({
      content: updatedContent
    })
  });

  const data = await response.json();
  if (!response.ok) {
    alert(data.error);
  }
}

async function deleteCourseSphereChat(chatId: string, messageId: string) {
  if (!ensureUserLoggedIn()) return;
  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_BASE_URL}/chats/${encodeURIComponent(chatId)}/messages/${encodeURIComponent(messageId)}`, {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`
    }
  });

  const data = await response.json();
  if (!response.ok) {
    alert(data.error);
  }
}

async function h(data: any): Promise<string | undefined> {
  if (!ensureUserLoggedIn()) return;

  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_BASE_URL}/hash`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`
    },
    body: JSON.stringify(data)
  });

  if (!response.ok) {
    throw new Error(`Error generating message ID: ${response.statusText}`);
  }

  const result = await response.json();
  return result.messageID;
}


export {
  createUser,
  performSignup,
  performLogin,
  saveProfileChanges,
  setProfileInfoIfLoggedIn,
  fetchCourseSphereResponse,
  saveCourseSphereChat,
  updateCourseSphereChat,
  deleteCourseSphereChat,
  h,
  database
};
