document.addEventListener("DOMContentLoaded", () => {
  const mainContent = document.getElementById("mainContent");
  const overviewBtn = document.getElementById("overviewBtn");
  const uploadsBtn = document.getElementById("uploadsBtn");
  const favoritesBtn = document.getElementById("favoritesBtn");

  overviewBtn.addEventListener("click", () => {
    mainContent.innerHTML = `
      <h1>Overview</h1>
      <p>Welcome to <strong>Edify</strong> — a collaborative educational platform where teachers can share, upload, and favorite valuable learning materials.</p>
      <ul>
          <li><strong>Uploads:</strong> Share your educational materials and resources.</li>
          <li><strong>Favorites:</strong> Save your favorite lessons for easy access.</li>
          <li><strong>Profile:</strong> Manage your educator profile and settings.</li>
      </ul>
    `;
  });

  uploadsBtn.addEventListener("click", () => {
    mainContent.innerHTML = `
      <h1>Uploads</h1>
      <p>Upload and manage your educational content here. You can share lessons, modules, or activities with other educators.</p>
      <button style="padding:10px 20px; background:#7a82fb; border:none; border-radius:6px; color:white; cursor:pointer;">Upload File</button>
    `;
  });

  favoritesBtn.addEventListener("click", () => {
    mainContent.innerHTML = `
      <h1>Favorites</h1>
      <p>Your saved favorite resources will appear here for quick access.</p>
      <div class="empty-state">
        <h2>You haven’t favorited anything yet.</h2>
        <p>Save lessons, modules, and activities you love to easily find them later.</p>
        <button style="padding:10px 20px; background:#7a82fb; border:none; border-radius:6px; color:white; cursor:pointer;">Explore & Save</button>
      </div>
    `;
  });
});
