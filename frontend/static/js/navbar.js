document.addEventListener("DOMContentLoaded", () => {
    // Selects all menu items for handling clicks
    const menuItems = document.querySelectorAll(".menu li");

    // Loop through each menu item to attach a click listener
    menuItems.forEach((item) => {
        item.addEventListener("click", () => {
            // 1. Remove 'active' class from all list items
            document.querySelectorAll(".menu li").forEach((li) => li.classList.remove("active"));
            
            // 2. Add 'active' class to the clicked item
            item.classList.add("active");
        });
    });
});