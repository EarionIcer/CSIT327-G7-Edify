// document.addEventListener("DOMContentLoaded", () => {
//   // Highlight active page (already handled by Django, this just animates)
//   const links = document.querySelectorAll(".menu li a");
//   links.forEach((link) => {
//     link.addEventListener("click", () => {
//       links.forEach((l) => l.parentElement.classList.remove("active"));
//       link.parentElement.classList.add("active");
//     });
//   });
// });

document.addEventListener("DOMContentLoaded", () => {
  // Highlight active page (already handled by Django, this just animates)
  const links = document.querySelectorAll(".menu li a");
  links.forEach((link) => {
    link.addEventListener("click", () => {
      links.forEach((l) => l.parentElement.classList.remove("active"));
      link.parentElement.classList.add("active");
    });
  });
});