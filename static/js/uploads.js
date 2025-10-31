// ====== Uploads Page Interactivity ======

// === DOM Elements ===
const searchBtn = document.getElementById("searchBtn");
const searchInput = document.getElementById("searchInput");
const filterBtn = document.getElementById("filterBtn");
const filterSelect = document.getElementById("filterSelect");
const tableBody = document.querySelector("tbody");
const tableRows = document.querySelectorAll("tbody tr");

// Create "no results" and "empty" messages
const noResultsRow = document.createElement("tr");
noResultsRow.classList.add("empty-row");
noResultsRow.innerHTML = `<td colspan="6" class="empty">No results found.</td>`;

const noFilesRow = document.createElement("tr");
noFilesRow.classList.add("empty-row");
noFilesRow.innerHTML = `<td colspan="6" class="empty">No files uploaded yet.</td>`;

// === Initialize Empty State ===
function checkInitialEmptyState() {
  if (tableRows.length === 0) {
    tableBody.appendChild(noFilesRow);
  }
}
checkInitialEmptyState();

// === Search Bar Toggle ===
searchBtn.addEventListener("click", () => {
  searchInput.classList.toggle("active");
  if (searchInput.classList.contains("active")) {
    searchInput.focus();
  } else {
    searchInput.value = "";
    resetFilter();
  }
});

// === Filter Dropdown Toggle ===
filterBtn.addEventListener("click", () => {
  filterSelect.classList.toggle("active");
});

// === Search & Filter Logic ===
function filterTable() {
  const query = searchInput.value.toLowerCase().trim();
  const filterValue = filterSelect.value.toLowerCase();
  let visibleCount = 0;

  tableRows.forEach(row => {
    const rowText = row.textContent.toLowerCase();
    const subjectCell = row.cells[3]?.textContent.toLowerCase() || "";

    const matchesSearch = rowText.includes(query);
    const matchesFilter = !filterValue || subjectCell.includes(filterValue);

    if (matchesSearch && matchesFilter) {
      row.style.display = "";
      visibleCount++;
    } else {
      row.style.display = "none";
    }
  });

  // Show or hide "no results" message
  const existingNoResults = document.querySelector(".empty-row");
  if (visibleCount === 0 && tableRows.length > 0) {
    if (!existingNoResults) tableBody.appendChild(noResultsRow);
  } else if (existingNoResults) {
    existingNoResults.remove();
  }
}

function resetFilter() {
  tableRows.forEach(row => (row.style.display = ""));
  const existingMessage = document.querySelector(".empty-row");
  if (existingMessage) existingMessage.remove();
}

// === Event Listeners ===
searchInput.addEventListener("keyup", filterTable);
filterSelect.addEventListener("change", filterTable);


document.addEventListener('DOMContentLoaded', () => {
  const fileInput = document.getElementById('fileInput');

  if (!fileInput) return;

  fileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/upload_file/', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();
      alert(result.message || result.error);

      // OPTIONAL: refresh file list dynamically
      if (result.message) {
        console.log('File uploaded successfully:', file.name);
        // You can later call a function here to refresh the table dynamically
      }
    } catch (error) {
      console.error('Upload failed:', error);
      alert('Error uploading file.');
    }
  });
});
