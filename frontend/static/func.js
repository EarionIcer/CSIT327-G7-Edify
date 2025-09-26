// func.js

function togglePassword(id) {
  const input = document.getElementById(id);
  if (input.type === "password") {
    input.type = "text";
  } else {
    input.type = "password";
  }
}

// Simple client-side validation
document.getElementById("registerForm").addEventListener("submit", function(e) {
  const pass = document.getElementById("password").value;
  const confirmPass = document.getElementById("confirm_password").value;

  if (pass !== confirmPass) {
    e.preventDefault();
    alert("Passwords do not match!");
  }
});
