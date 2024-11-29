document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.querySelector("#password");
    const clearIconPassword = document.querySelector("#clear-icon-password");

    passwordInput.addEventListener("input", () => {
        clearIconPassword.style.visibility = passwordInput.value ? "visible" : "hidden";
    });

    clearIconPassword.addEventListener("click", () => {
        passwordInput.value = "";
        clearIconPassword.style.visibility = "hidden";
    });
});
