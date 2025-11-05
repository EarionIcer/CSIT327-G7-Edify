// func.js

// function togglePassword(id, el) {
//   const input = document.getElementById(id);
//   const icon = el.querySelector("ion-icon");

//   if (input.type === "password") {
//     input.type = "text";
//     icon.setAttribute("name", "eye-off-outline");
//   } else {
//     input.type = "password";
//     icon.setAttribute("name", "eye-outline");
//   }
// }

// document.getElementById("registerForm").addEventListener("submit", function(e) {
//   const pass = document.getElementById("password").value;
//   const confirmPass = document.getElementById("confirm_password").value;

//   if (pass !== confirmPass) {
//     e.preventDefault();
//     alert("Passwords do not match!");
//   }
// });



// function togglePassword(id, el) {
//   const input = document.getElementById(id);
//   // Get the element's text content (the emoji)
//   const icon = el.textContent.trim();

//   if (input.type === "password") {
//     input.type = "text";
//     // Change eye to closed eye emoji
//     el.textContent = "🙈"; 
//   } else {
//     input.type = "password";
//     // Change closed eye back to open eye emoji
//     el.textContent = "👁️";
//   }
// }

// document.getElementById("registerForm").addEventListener("submit", function(e) {
//   let isValid = true;

//   const email = document.getElementById("email").value;
//   const pass = document.getElementById("password").value;
//   const confirmPass = document.getElementById("confirm_password").value;
//   const emailError = document.getElementById("email-error");
//   const passwordError = document.getElementById("password-error");
//   const confirmPasswordError = document.getElementById("confirm-password-error");
  
//   // Helper to clear error state
//   function clearError(element) {
//       element.textContent = "";
//       element.classList.remove('active');
//   }

//   // Helper to show error state
//   function showError(element, message) {
//       element.textContent = message;
//       element.classList.add('active'); // Add the active class to show it
//       isValid = false;
//   }

//   // --- Clear previous errors and classes ---
//   clearError(emailError);
//   clearError(passwordError);
//   clearError(confirmPasswordError);

//   // --- Email Validation ---
//   const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//   if (!emailRegex.test(email)) {
//     showError(emailError, "Please enter a valid email address.");
//   }

//   // --- Password Length Validation ---
//   if (pass.length < 8) {
//     showError(passwordError, "Password must be at least 8 characters long.");
//   }

//   // --- Confirm Password Validation ---
//   if (pass !== confirmPass) {
//     showError(confirmPasswordError, "Warning: Passwords do not match!");
//   }

//   // Prevent form submission if not valid
//   if (!isValid) {
//     e.preventDefault();
//   }
// });


// static/js/func.js

document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form");
  const errorMsg = document.createElement("p");
  errorMsg.style.color = "red";
  errorMsg.style.textAlign = "center";
  form.prepend(errorMsg);

  form.addEventListener("submit", (e) => {
    const email = document.getElementById("email").value.trim();
    const pass = document.getElementById("password").value.trim();
    const confirm = document.getElementById("confirmPassword")?.value.trim();

    errorMsg.textContent = "";

    // Gmail validation
    const gmailPattern = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    if (!gmailPattern.test(email)) {
      e.preventDefault();
      errorMsg.textContent = "Please enter a valid Gmail address.";
      return;
    }

    // Confirm password validation (only if field exists)
    if (confirm !== undefined && pass !== confirm) {
      e.preventDefault();
      errorMsg.textContent = "Passwords do not match.";
    }
  });
});


