// Typing Effect
const roles = [
  "Cybersecurity Expert",
  "Bug Bounty Hunter",
  "API Security Specialist",
  "Breaking Systems Securely 🔥"
];

let i = 0, j = 0, current = "", deleting = false;

function type() {
  current = roles[i];

  if (deleting) j--;
  else j++;

  document.querySelector(".typing").textContent = current.substring(0, j);

  if (!deleting && j === current.length) {
    deleting = true;
    setTimeout(type, 1000);
    return;
  }

  if (deleting && j === 0) {
    deleting = false;
    i = (i + 1) % roles.length;
  }

  setTimeout(type, deleting ? 50 : 100);
}
type();


// Particles
tsParticles.load("particles", {
  particles: {
    number: { value: 80 },
    color: { value: "#00ffff" },
    links: { enable: true, color: "#00ffff" },
    move: { enable: true }
  }
});


// Resume
function downloadResume() {
  window.open("resume.pdf");
}


// Chat Toggle
function toggleChat() {
  const box = document.getElementById("chatbox");
  box.style.display = box.style.display === "block" ? "none" : "block";
}


// Simple AI Chat (local)
function handleChat(e) {
  if (e.key === "Enter") {
    let input = e.target.value;
    let body = document.getElementById("chatBody");

    body.innerHTML += `<p><b>You:</b> ${input}</p>`;

    let reply = "I am Vijay's portfolio assistant.";

    if (input.toLowerCase().includes("skills")) reply = "VAPT, API Security, Cloud.";
    if (input.toLowerCase().includes("contact")) reply = "Email: vijay@example.com";

    body.innerHTML += `<p><b>Bot:</b> ${reply}</p>`;
    e.target.value = "";
  }
}
